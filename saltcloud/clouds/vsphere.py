'''
vSphere Cloud Module
======================

'''

# Import python libs
import os
import logging
import socket
import pprint

# Imprt pysphere
from pysphere import VIServer, MORTypes, VITask
from pysphere.resources import VimService_services as VI

# Import salt libs
import salt.utils

# Get logging started
log = logging.getLogger(__name__)


# Only load in this module if the VSPHERE configurations are in place.
def __virtual__():
    '''
    Set up the pysphere functions and check for VSPHERE configurations.
    '''
    if get_configured_provider() is False:
        log.debug(
            'There is no vSphere cloud provider configuration available. '
            'Not loading module.'
        )
        return False

    log.debug('Loading vSphere cloud module')
    return 'vsphere'


def get_configured_provider():
    '''
    Return the first configured instance.
    '''
    return config.is_provider_configured(
        __opts__,
        __active_provider_name__ or 'vsphere',
        ('hostname', 'username', 'password')
    )


def get_server():
    '''
    Return a server object.
    '''
    server = VIServer()

    hostname = config.get_config_value('hostname', get_configured_provider(), __opts__, search_global=False)
    username = config.get_config_value('username', get_configured_provider(), __opts__, search_global=False)
    password = config.get_config_value('password', get_configured_provider(), __opts__, search_global=False)

    server.connect(hostname, username, password)

    return server


def get_datastore(vm_):
    '''
    Return the datastore name.
    '''
    return config.get_config_value('datastore', vm_, __opts__, search_global=False)


def get_os(vm_):
    '''
    Return the OS type string.
    '''
    return config.get_config_value('os', vm_, __opts__, default='otherGuest', search_global=False)


def get_cpus(vm_):
    '''
    Return the cpu count.
    '''
    return config.get_config_value('cpus', vm_, __opts__, default=1, search_global=False)


def get_memory(vm_):
    '''
    Return the memory size.
    '''
    return config.get_config_value('memory', vm_, __opts__, default=1024, search_global=False)


def get_disks(vm_):
    '''
    Return the disks object.
    '''
    return config.get_config_value('disks', vm_, __opts__, default={}, search_global=False)


def get_nics(vm_):
    '''
    Return the nics object.
    '''
    return config.get_config_value('nics', vm_, __opts__, default={}, search_global=False)


def get_destination_folder(vm_, server):
    '''
    Return the destination folder object.
    '''
    destination_folder = config.get_config_value(
        'destination_folder', vm_, __opts__, search_global=False
    )

    folders = server._get_managed_objects(MORTypes.Folder)

    # Search for destination folder.
    destination_mor = None
    for mor, folder_name in folders.items():
        if folder_name == destination_folder:
            destination_mor = mor
            break

    return destination_mor


def get_resource_pool(vm_, server):
    '''
    Return the resource pool object.
    '''
    path = config.get_config_value(
        'resource_pool', vm_, __opts__, search_global=False
    )

    pool = None
    for k, v in server.get_resource_pools().items():
        if v == path:
            pool = v
            break

    return pool


def create(vm_=None, call=None):
    '''
    Create a single VM from a data dict.
    '''
    if call:
        raise SaltCloudSystemExit(
            'You cannot create an instance with -a or -f.'
        )

    saltcloud.utils.fire_event(
        'event',
        'starting create',
        "salt/cloud/{0}/creating".format(vm_['name']),
        {
            'name': vm_['name'],
            'profile': vm_['profile'],
            'provider': vm_['provider'],
        },
    )

    log.info("Creating Cloud VM {0}".format(vm_['name']))

    # The following is based on the mailing list discussion here:
    # https://groups.google.com/forum/#!searchin/pysphere/create$20new$20vm/pysphere/VF9pN9qU-94/1fQoKTx-mLUJ

    server = get_server()
    datastore = get_datastore(vm_)
    destination_folder = get_destination_folder(vm_, server)
    resource_pool = get_resource_pool(vm_, server)

    class Lambda:
        pass

    create_vm = Lambda()
    create_vm.request = VI.CreateVM_TaskRequestMsg()
    create_vm.config = create_vm.request.new_config()
    create_vm.request.set_element_config(create_vm.config)

    create_vm.files = create_vm.config.new_files()
    create_vm.files.set_element_vmPathName("[{0}] {1}/{1}.vmx".format(datastore, vm_['name']))
    create_vm.config.set_element_files(create_vm.files)

    create_vm.config.set_element_name(vm_['name'])

    create_vm.folder = create_vm.request.new__this(destination_folder)
    create_vm.folder.set_attribute_type(destination_folder.get_attribute_type())
    create_vm.request.set_element__this(create_vm.folder)

    create_vm.resource_pool = create_vm.request.new_pool(resource_pool)
    create_vm.resource_pool.set_attribute_type(resource_pool.get_attribute_type())
    create_vm.request.set_element_pool(create_vm.resource_pool)

    # Send create vm request.
    task = VITask(server._proxy.CreateVM_Task(create_vm.request)._returnval, server)
    task.wait_for_state([task.STATE_SUCCESS, task.STATE_ERROR])
    if task.get_state() == task.STATE_ERROR:
        log.error("Error creating {0} on VSPHERE\n\n{1}".format(vm_['name'], task.get_error_message()))
        return False
    server.disconnect()

    # Construct return data.
    ret = {
        'name': vm_['name']
    }

    log.info("Created Cloud VM {0}".format(vm_['name']))
    log.debug("{0} VM creation details:\n{1}".format(vm_['name'], pprint.pformat(ret)))

    return ret
