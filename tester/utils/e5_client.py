"""Fixed-rate read-only clients for the E5 container capacity baseline."""

import asyncio
from array import array
from contextlib import AsyncExitStack
import json
import math
from pathlib import Path
import random
import sys
import time


async def connections(config, resources, count):
  service, port = config['service'], config['port']
  timeout = config.get('request_timeout_s', 2)
  if service == 'nginx':
    import aiohttp
    session = await resources.enter_async_context(aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(limit=count), timeout=aiohttp.ClientTimeout(total=timeout)))
    async def request(key):
      async with session.get(f'http://127.0.0.1:{port}/') as response:
        if response.status != 200 or len(await response.read()) != config.get('response_bytes', 1024):
          raise ValueError('unexpected HTTP response')
    return [request] * count
  if service == 'redis':
    import redis.asyncio as redis
    client = redis.Redis(host='127.0.0.1', port=port, max_connections=count, socket_timeout=timeout)
    resources.push_async_callback(client.aclose)
    await client.ping()
    async def request(key):
      if len(await client.get(str(key))) != config.get('payload_bytes', 256):
        raise ValueError('unexpected Redis value')
    return [request] * count
  if service == 'mongo':
    from pymongo import AsyncMongoClient
    client = AsyncMongoClient('127.0.0.1', port, maxPoolSize=count,
                             serverSelectionTimeoutMS=round(timeout * 1000), socketTimeoutMS=round(timeout * 1000))
    resources.push_async_callback(client.close)
    await client.admin.command('ping')
    async def request(key):
      result = await client.e5.items.find_one({'_id': key})
      if len(result['payload']) != config.get('payload_bytes', 256):
        raise ValueError('unexpected MongoDB value')
    return [request] * count
  import psycopg
  requests = []
  for _ in range(count):
    connection = await psycopg.AsyncConnection.connect(host='127.0.0.1', port=port, user='e5',
        password=config['password'], dbname='e5', autocommit=True,
        connect_timeout=max(1, math.ceil(config.get('request_timeout_s', 2))))
    resources.push_async_callback(connection.close)
    async def request(key, connection=connection):
      cursor = await connection.execute('SELECT payload FROM items WHERE id = %s', (key,))
      row = await cursor.fetchone()
      if len(row[0]) != config.get('payload_bytes', 256):
        raise ValueError('unexpected PostgreSQL value')
    requests.append(request)
  return requests


async def seed(config):
  async with AsyncExitStack() as resources:
    service, port = config['service'], config['port']
    if service == 'redis':
      import redis.asyncio as redis
      client = redis.Redis(host='127.0.0.1', port=port)
      resources.push_async_callback(client.aclose)
      async with client.pipeline(transaction=False) as pipeline:
        for key in range(config.get('records', 10000)):
          pipeline.set(str(key), b'x' * config.get('payload_bytes', 256))
        await pipeline.execute()
    elif service == 'mongo':
      from pymongo import AsyncMongoClient
      client = AsyncMongoClient('127.0.0.1', port, serverSelectionTimeoutMS=2000)
      resources.push_async_callback(client.close)
      rows = [{'_id': key, 'payload': 'x' * config.get('payload_bytes', 256)}
              for key in range(config.get('records', 10000))]
      await client.e5.items.insert_many(rows)
    elif service == 'postgres':
      import psycopg
      connection = await psycopg.AsyncConnection.connect(host='127.0.0.1', port=port, user='e5',
          password=config['password'], dbname='e5', autocommit=True,
          connect_timeout=max(1, math.ceil(config.get('request_timeout_s', 2))))
      resources.push_async_callback(connection.close)
      await connection.execute('CREATE TABLE items (id integer PRIMARY KEY, payload text NOT NULL)')
      await connection.execute("INSERT INTO items SELECT id, repeat('x', %s) FROM generate_series(0, %s) id",
          (config.get('payload_bytes', 256), config.get('records', 10000) - 1))
      await connection.execute('ANALYZE items')
    request = (await connections(config, resources, 1))[0]
    await request(0)
  print('seeded', flush=True)


async def benchmark(config):
  directory = Path(config['output'])
  latency, service_time = array('Q'), array('Q')
  admission_lag, queue_wait = array('Q'), array('Q')
  halves = [array('Q'), array('Q')]
  errors, skipped, scheduled, late = [], 0, 0, 0
  queue = asyncio.Queue(maxsize=config.get('queue_capacity', 64))
  queue_peak = 0
  rng = random.Random(config['seed'])
  async with AsyncExitStack() as resources:
    requests = await connections(config, resources, config.get('connections_per_shard', 8))
    async def consume(request):
      nonlocal late
      while (job := await queue.get()) is not None:
        due, measured, admitted = job
        start = time.monotonic_ns()
        try:
          await asyncio.wait_for(request(rng.randrange(config.get('records', 10000))),
                                 timeout=config.get('request_timeout_s', 2))
        except Exception as error:
          if measured:
            errors.append(f'{type(error).__name__}: {error}')
        else:
          end = time.monotonic_ns()
          if measured:
            latency.append(end - due)
            service_time.append(end - start)
            queue_wait.append(start - admitted)
            halves[int(due >= (config['measure_ns'] + config['end_ns']) // 2)].append(end - due)
            late += end > config['end_ns']
        finally:
          queue.task_done()
    tasks = [asyncio.create_task(consume(request)) for request in requests]
    print('ready', flush=True)
    if 'start_file' in config:
      (directory / 'ready').touch()
      gate = Path(config['start_file'])
      deadline = time.monotonic() + config['startup_timeout_s']
      while not gate.exists():
        if time.monotonic() >= deadline:
          raise TimeoutError('client start gate timed out')
        await asyncio.sleep(.01)
      config.update(json.loads(gate.read_text()))
    i = 0
    while True:
      due = config['start_ns'] + int((i + config['phase']) * 1e9 / config['rate'])
      if due >= config['end_ns']:
        break
      delay = (due - time.monotonic_ns()) / 1e9
      if delay > 0:
        await asyncio.sleep(delay)
      measured = due >= config['measure_ns']
      scheduled += measured
      admitted = time.monotonic_ns()
      if measured:
        admission_lag.append(max(0, admitted - due))
      try:
        queue.put_nowait((due, measured, admitted))
        queue_peak = max(queue_peak, queue.qsize())
      except asyncio.QueueFull:
        skipped += measured
      i += 1
    await queue.join()
    for _ in tasks:
      await queue.put(None)
    await asyncio.gather(*tasks)
  for name, values in [('latency_ns', latency), ('service_ns', service_time),
                       ('admission_lag_ns', admission_lag), ('queue_wait_ns', queue_wait)]:
    with (directory / (name + '.bin')).open('wb') as output:
      values.tofile(output)
  values = sorted(latency)
  report = {'scheduled': scheduled, 'completed': len(values), 'skipped': skipped,
            'errors': errors[:30], 'error_count': len(errors), 'completed_after_window': late,
            'sample_type': 'native-endian unsigned 64-bit nanoseconds', 'byteorder': sys.byteorder,
            'latency_includes': 'scheduled arrival through response, including client queueing',
            'p99_ms': values[math.ceil(.99 * len(values)) - 1] / 1e6 if values else None,
            'max_ms': max(values) / 1e6 if values else None}
  report.update(queue_capacity=queue.maxsize, queue_peak=queue_peak,
                max_admission_lag_ms=max(admission_lag) / 1e6 if admission_lag else None,
                max_queue_wait_ms=max(queue_wait) / 1e6 if queue_wait else None)
  report['half_p99_ms'] = [sorted(part)[math.ceil(.99 * len(part)) - 1] / 1e6 if part else None
                           for part in halves]
  (directory / 'client.json').write_text(json.dumps(report, indent=2) + '\n')
  print('done', flush=True)


if __name__ == '__main__':
  config = json.loads(Path(sys.argv[2]).read_text())
  asyncio.run(seed(config) if sys.argv[1] == 'seed' else benchmark(config))
