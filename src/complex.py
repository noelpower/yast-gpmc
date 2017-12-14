from samba import smb
from configparser import ConfigParser
from io import StringIO
import xml.etree.ElementTree as etree
import os.path, sys
from samba.net import Net
from samba.dcerpc import nbt
from subprocess import Popen, PIPE
import uuid
import re
from ldap3 import Server, Connection, Tls, SASL, KERBEROS, ALL, SUBTREE,  ALL_ATTRIBUTES

# the existing code expects the ldap results to come back
# as a list of tuples where each tuple (for each entry in the results)
# is (string(dn), dict(attributes)
#    where the dictionay of attributes is in a 'raw' form e.g. all
#    attribute values are lists of values where each value is a string
#    representation of the value. ldap3 has a more sophisticated representation.
#    For the moment lets just present things how the old code would see it
def mod_ldapify_result(entries):
    result = []
    i = 0
    for entry in entries:
        dn = entry['dn']
        attrs = {}
        for key in entry['raw_attributes'].keys():
            new_attrs_list = []
            for val in entry['raw_attributes'][key]:
                 #print ("entry[%d][%s] has value type %s with %s"%(i, key, type(val), val))

                 try:
                     new_attrs_list.append(val.decode())
                 except:
                     #print("failed to decode %s, leaving it as bytes"%val)
                     new_attrs_list.append(val)
                 #print ("new_value = %s"%new_attrs_list[-1])
            attrs[key] = new_attrs_list
        result.append(tuple([dn, attrs]))
        i = i + 1
    return result

class GPConnection:
    def __init__(self, lp, creds):
        self.lp = lp
        self.creds = creds
        self.realm = lp.get('realm')
        net = Net(creds=creds, lp=lp)
        cldap_ret = net.finddc(domain=self.realm, flags=(nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS))
        self.sasl_bind_working = False
        if self.__kinit_for_gssapi():
            # #FIXME this is just temporary code to get us over the fact
            # that sasl bind isn't working  
            if self.sasl_bind_working:
                self.server = Server(cldap_ret.pdc_dns_name, use_ssl=True, tls=tls)
                self.conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS)
            else:
                # #FIXME test code, this passess username and password over
                # the network in clear text 
                self.server = Server(cldap_ret.pdc_dns_name, get_info=ALL)
                self.conn = Connection(self.server, user='%s@%s' % (self.creds.get_username(), self.realm) if not self.realm in self.creds.get_username() else self.creds.get_username(), password = self.creds.get_password())
        else:
            # #FIXME I think this should be removed in a production system
            # and we should just error out, otherwise we are transmitting
            # passwords in cleartext 
            self.server = Server(cldap_ret.pdc_dns_name, get_info=ALL)
            self.conn = Connection(server, user='%s@%s' %s (self.creds.get_username(), self.realm) if not self.realm in self.creds.get_username() else self.creds.get_username(), password = self.creds.get_password())

        self.conn.bind()

    def __kinit_for_gssapi(self):
        p = Popen(['kinit', '%s@%s' % (self.creds.get_username(), self.realm) if not self.realm in self.creds.get_username() else self.creds.get_username()], stdin=PIPE, stdout=PIPE)
        p.stdin.write(('%s\n'%self.creds.get_password()).encode())
        p.stdin.flush()
        return p.wait() == 0

    def realm_to_dn(self, realm):
        return ','.join(['DC=%s' % part for part in realm.lower().split('.')])

    def __well_known_container(self, container):
        result = None
        if container == 'system':
            wkguiduc = 'AB1D30F3768811D1ADED00C04FD8D5CD'
        elif container == 'computers':
            wkguiduc = 'AA312825768811D1ADED00C04FD8D5CD'
        elif container == 'dcs':
            wkguiduc = 'A361B2FFFFD211D1AA4B00C04FD7D83A'
        elif container == 'users':
            wkguiduc = 'A9D1CA15768811D1ADED00C04FD8D5CD'
        self.conn.search('<WKGUID=%s,%s>' % (wkguiduc, self.realm_to_dn(self.realm)), '(objectClass=container)', SUBTREE, attributes = ['distinguishedName'])
        if self.conn.result['result'] == 0 and len(self.conn.response) and len(self.conn.response[0]['attributes']):
            result = self.conn.response[0]['attributes']['distinguishedName']
        return result

    def gpo_list(self):

        self.conn.search(self.__well_known_container('system'),
                   '(objectCategory=groupPolicyContainer)',
                    SUBTREE,
                    attributes = ALL_ATTRIBUTES)
        result = None
        if self.conn.result['result'] == 0 and len(self.conn.response) and len(self.conn.response[0]['attributes']):
                result = mod_ldapify_result(self.conn.response)
        return result

    def set_attr(self, dn, key, value):
        self.l.modify(dn, [(1, key, None), (0, key, value)])

    def create_gpo(self, displayName):
        gpouuid = uuid.uuid4()
        realm_dn = self.realm_to_dn(self.realm)
        name = '{%s}' % str(gpouuid).upper()
        dn = 'CN=%s,CN=Policies,CN=System,%s' % (name, realm_dn)
        ldap_mod = { 'displayName': [displayName], 'gPCFileSysPath': ['\\\\%s\\SysVol\\%s\\Policies\\%s' % (self.realm, self.realm, name)], 'objectClass': ['top', 'container', 'groupPolicyContainer'], 'gPCFunctionalityVersion': ['2'], 'flags': ['0'], 'versionNumber': ['0'] }
        # gPCMachineExtensionNames MUST be assigned as gpos are modified (currently not doing this!)

        machine_dn = 'CN=Machine,%s' % dn
        user_dn = 'CN=User,%s' % dn
        sub_ldap_mod = { 'objectClass': ['top', 'container'] }

        gpo = GPOConnection(self.lp, self.creds, ldap_mod['gPCFileSysPath'][-1])
        try:
            self.l.add_s(dn, addlist(ldap_mod))
            self.l.add_s(machine_dn, addlist(sub_ldap_mod))
            self.l.add_s(user_dn, addlist(sub_ldap_mod))

            gpo.initialize_empty_gpo()
            # TODO: GPO links
        except Exception as e:
            print(str(e))

class GPOConnection(GPConnection):
    def __init__(self, lp, creds, gpo_path):
        GPConnection.__init__(self, lp, creds)
        path_parts = [n for n in gpo_path.split('\\') if n]
        self.path_start = '\\\\' + '\\'.join(path_parts[:2])
        self.path = '\\'.join(path_parts[2:])
        self.name = path_parts[-1]
        self.realm_dn = self.realm_to_dn(self.realm)
        self.gpo_dn = 'CN=%s,CN=Policies,CN=System,%s' % (self.name, self.realm_dn)
        try:
            self.conn = smb.SMB(path_parts[0], path_parts[1], lp=self.lp, creds=self.creds)
        except:
            self.conn = None

    def update_machine_gpe_ini(self, extension):
        ini_conf = self.parse('Group Policy\\GPE.INI')
        if not ini_conf.has_section('General'):
            ini_conf.add_section('General')
        machine_extension_versions = ''
        if ini_conf.has_option('General', 'MachineExtensionVersions'):
            machine_extension_versions = ini_conf.get('General', 'MachineExtensionVersions').encode('ascii')
        itr = re.finditer('\[%s:\d+]' % extension, machine_extension_versions)
        try:
            new_ext_str = machine_extension_versions[:m.start()] + machine_extension_versions[m.end():]
            machine_extension_versions = new_ext_str
        except:
            pass

        _, version = self.__get_gpo_version()
        machine_extension_versions += '[%s:%d]' % (extension, version-1)
        ini_conf.set('General', 'MachineExtensionVersions', machine_extension_versions)
        self.write('Group Policy\\GPE.INI', ini_conf)

    def initialize_empty_gpo(self):
        self.__smb_mkdir_p('\\'.join([self.path, 'MACHINE']))
        self.__smb_mkdir_p('\\'.join([self.path, 'USER']))
        self.__increment_gpt_ini()

    def __get_gpo_version(self, ini_conf=None):
        if not ini_conf:
            ini_conf = self.parse('GPT.INI')
        current = 0
        cur_user = 0
        cur_comp = 0
        if ini_conf.has_option('General', 'Version'):
            current = int(ini_conf.get('General', 'Version').encode('ascii'))
            cur_user = current >> 16
            cur_comp = current & 0x0000FFFF
        return (cur_user, cur_comp)

    def __increment_gpt_ini(self, user=False, computer=False):
        ini_conf = self.parse('GPT.INI')
        cur_user, cur_comp = self.__get_gpo_version(ini_conf)
        if user:
            cur_user += 1
        if computer:
            cur_comp += 1
        current = (cur_user << 16) + cur_comp

        if not ini_conf.has_section('General'):
            ini_conf.add_section('General')
        ini_conf.set('General', 'Version', current)
        self.write('GPT.INI', ini_conf)

        self.set_attr(self.gpo_dn, 'versionNumber', current)

    def parse(self, filename):
        if len(re.findall('CN=[A-Za-z ]+,', filename)) > 0:
            return self.__parse_dn(filename)
        else:
            ext = os.path.splitext(filename)[-1].lower()
            if ext in ['.inf', '.ini', '.ins']:
                return self.__parse_inf(filename)
            elif ext == '.xml':
                return self.__parse_xml(filename)
            return ''

    def write(self, filename, config):
        if len(re.findall('CN=[A-Za-z ]+,', filename)) > 0:
            self.__write_dn(filename, config)
        else:
            ext = os.path.splitext(filename)[-1].lower()
            if ext in ['.inf', '.ini', '.ins']:
                self.__write_inf(filename, config)
            elif ext == '.xml':
                self.__write_xml(filename, config)

            if '\\machine' in filename.lower():
                self.__increment_gpt_ini(computer=True)
            elif '\\user' in filename.lower():
                self.__increment_gpt_ini(user=True)

    def __parse_dn(self, dn):
        dn = dn % self.gpo_dn
        try:
            resp = []
            self.conn.search(dn, '(objectCategory=packageRegistration)', SUBTREE, attributes = ALL_ATTRIBUTES)
            if self.conn.result['result'] == 0 and len(self.conn.response) and len(self.conn.response[0]['attributes']):
                resp = mod_ldapify_result(self.conn.response)
            keys = ['objectClass', 'msiFileList', 'msiScriptPath', 'displayName', 'versionNumberHi', 'versionNumberLo']
            results = {a[-1]['name'][-1]: {k: a[-1][k] for k in a[-1].keys() if k in keys} for a in resp}
        except Exception as e:
            if 'No such object' in str(e):
                results = {}
            else:
                raise
        return results

    def __mkdn_p(self, dn):
        attrs = { 'objectClass' : ['top', 'container'] }
        try:
            self.l.add_s(dn, addlist(attrs))
        except Exception as e:
            if e.args[-1]['desc'] == 'No such object':
                self.__mkdn_p(','.join(dn.split(',')[1:]))
            elif e.args[-1]['desc'] == 'Already exists':
                return
            else:
                sys.stderr.write(e.args[-1]['info'])
        try:
            self.l.add_s(dn, addlist(attrs))
        except Exception as e:
            if e.args[-1]['desc'] != 'Already exists':
                sys.stderr.write(e.args[-1]['info'])

    def __write_dn(self, dn, ldap_config):
        for cn in ldap_config.keys():
            obj_dn = 'CN=%s,%s' % (cn, dn % self.gpo_dn)
            if 'objectClass' not in ldap_config[cn]:
                ldap_config[cn]['objectClass'] = ['top', 'packageRegistration']
            if 'msiFileList' not in ldap_config[cn]:
                ldap_config[cn]['msiFileList'] = os.path.splitext(ldap_config[cn]['msiScriptPath'][-1])[0] + '.zap'
            self.__mkdn_p(','.join(obj_dn.split(',')[1:]))
            try:
                self.l.add_s(obj_dn, addlist(ldap_config[cn]))
            except Exception as e:
                if e.args[-1]['desc'] == 'Already exists':
                    try:
                        self.l.modify_s(obj_dn, modlist({}, ldap_config[cn]))
                    except Exception as e:
                        sys.stderr.write(e.args[-1]['info'])
                else:
                    sys.stderr.write(e.args[-1]['info'])

            if os.path.splitext(ldap_config[cn]['msiFileList'][-1])[-1] == '.zap':
                inf_conf = self.__parse_inf(ldap_config[cn]['msiFileList'][-1])
                if not inf_conf.has_section('Application'):
                    inf_conf.add_section('Application')
                inf_conf.set('Application', 'FriendlyName', ldap_config[cn]['displayName'][-1])
                inf_conf.set('Application', 'SetupCommand', 'rpm -i "%s"' % ldap_config[cn]['msiScriptPath'][-1])
                self.__write_inf(ldap_config[cn]['msiFileList'][-1], inf_conf)

    def __parse_inf(self, filename):
        inf_conf = ConfigParser()
        if self.conn:
            try:
                policy = self.conn.loadfile('\\'.join([self.path, filename]))
            except:
                policy = ''
            inf_conf.optionxform=str
            try:
                inf_conf.readfp(StringIO(policy))
            except:
                inf_conf.readfp(StringIO(policy.decode('utf-16')))
        return inf_conf

    def __parse_xml(self, filename):
        xml_conf = None
        if self.conn:
            try:
                policy = self.conn.loadfile('\\'.join([self.path, filename]))
                xml_conf = etree.fromstring(policy)
            except:
                xml_conf = None
        return xml_conf

    def __smb_mkdir_p(self, path):
        directory = os.path.dirname(path.replace('\\', '/')).replace('/', '\\')
        try:
            self.conn.mkdir(directory)
        except Exception as e:
            if e[0] == -1073741766: # 0xC000003A: STATUS_OBJECT_PATH_NOT_FOUND
                self.__smb_mkdir_p(directory)
            elif e[0] == -1073741771: # 0xC0000035: STATUS_OBJECT_NAME_COLLISION
                pass
            else:
                print(e[1])
        try:
            self.conn.mkdir(path)
        except Exception as e:
            if e[0] == -1073741771: # 0xC0000035: STATUS_OBJECT_NAME_COLLISION
                pass
            else:
                print(e[1])

    def __write(self, filename, text):
        path = '\\'.join([self.path, filename])
        filedir = os.path.dirname((path).replace('\\', '/')).replace('/', '\\')
        self.__smb_mkdir_p(filedir)
        try:
            self.conn.savefile(path, text)
        except Exception as e:
            if e[0] == -1073741766: # 0xC000003A: STATUS_OBJECT_PATH_NOT_FOUND
                print(e[1] % (path))
            else:
                print(e[1])

    def __write_inf(self, filename, inf_config):
        out = StringIO()
        inf_config.write(out)
        value = out.getvalue().replace('\n', '\r\n').encode('utf-16')
        self.__write(filename, value)

    def __write_xml(self, filename, xml_config):
        value = '<?xml version="1.0" encoding="utf-8"?>\r\n' + etree.tostring(xml_config, 'utf-8')
        self.__write(filename, value)

    def upload_file(self, local, remote_dir):
        remote_path = '\\'.join([self.path, remote_dir])
        self.__smb_mkdir_p(remote_path)
        if os.path.exists(local):
            value = open(local).read()
            filename = '\\'.join([remote_path, os.path.basename(local)])
            try:
                self.conn.savefile(filename, value)
            except Exception as e:
                if e[0] == -1073741771: # 0xC0000035: STATUS_OBJECT_NAME_COLLISION
                    sys.stderr.write('The file \'%s\' already exists at \'%s\' and could not be saved.' % (os.path.basename(local), remote_path))
                else:
                    sys.stderr.write(e[1])
            return filename

