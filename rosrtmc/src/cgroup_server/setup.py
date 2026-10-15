from setuptools import find_packages, setup

package_name = 'cgroup_server'

setup(
    name=package_name,
    version='0.0.0',
    packages=find_packages(exclude=['test']),
    py_modules=['sched_manager'],
    package_dir={'': '../../../tools', package_name: package_name},
    data_files=[
        ('share/ament_index/resource_index/packages',
            ['resource/' + package_name]),
        ('share/' + package_name, ['package.xml']),
    ],
    install_requires=['setuptools'],
    zip_safe=True,
    maintainer='alexy',
    maintainer_email='alexander.yoshida@gmail.com',
    description='TODO: Package description',
    license='TODO: License declaration',
    tests_require=['pytest'],
    entry_points={
        'console_scripts': [
            'cgroup_server = cgroup_server.cgroup_server:main'
        ],
    },
)
