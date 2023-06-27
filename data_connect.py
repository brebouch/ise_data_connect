import json
import jpype
import traceback
import sys
import jaydebeapi
import requests
import yaml
import utilities


class ISEDB:
    jar_path = ''
    tables = {}

    def query_db_table(self, table):
        self.logger.debug(f"Initiating query on table {table}")
        response = []
        if not self.cursor:
            raise ConnectionError('Cursor object not initialized')
        cols = list(self.tables[table].keys())
        query_attr = ','.join(cols)
        query = f'SELECT {query_attr} FROM {table}'
        self.cursor.execute(query)
        output = self.cursor.fetchall()
        self.logger.debug(f"Query on table {table} complete, total results: {str(len(output))}")
        for out in output:
            update = {}
            for index, o in enumerate(out):
                col = cols[index]
                data_type = self.tables[table][col]['type']
                item = None
                if data_type == 'VARCHAR2':
                    item = str(o)
                elif data_type == 'TIMESTAMP(6)':
                    pass
                elif data_type == 'TIMESTAMP(6) WITH TIME ZONE':
                    pass
                elif data_type == 'NUMBER':
                    item = int(o)
                elif data_type == 'CLOB':
                    pass
                elif data_type == 'BLOB':
                    pass
                update.update({col: item})
            response.append(update)
        return response

    def query_db(self, query):
        self.logger.debug(f"Initiating advanced query: {query}")
        if not self.cursor:
            raise ConnectionError('Cursor object not initialized')
        self.cursor.execute(query)
        output = self.cursor.fetchall()
        self.logger.debug(f"Advanced Query complete, total results: {str(len(output))}")
        return output

    def _get_pubhub_views(self):
        self.logger.debug(f"Pulling updated table views from Cisco Developer PubHub")
        resp = requests.get('https://pubhub.devnetcloud.com/media/dataconnect/docs/web.json?1681872359105')
        if resp.status_code == 200:
            pubhub_data = resp.json()
            for i in pubhub_data['items'][1]['nav']:
                self.tables.update({i['title']: {}})
            self.logger.debug(f"Updated table views from Cisco Developer PubHub")
        else:
            self.logger.critical(f"Pull from from Cisco Developer PubHub failed, check connectivity and try again")

    def get_all_db_tables(self):
        self.logger.debug(f"Pulling all DB tables")
        response = []
        if not self.cursor:
            self.logger.critical('Cursor object not initialized')
            raise ConnectionError('Cursor object not initialized')
        self.cursor.execute(f"SELECT * "
                            f"FROM all_views "
                            f"ORDER BY view_name")
        output = self.cursor.fetchall()
        self.logger.debug(f"Pull complete, {str(len(output))} tables found")
        for o in output:
            response.append(str(o[0]))
        return response

    def get_table_columns(self, table):
        self.logger.debug(f"Pulling columns for table: {table}")
        if not self.cursor:
            raise ConnectionError('Cursor object not initialized')
        self.cursor.execute(f"select column_name,data_type,data_length "
                            f"from all_tab_columns "
                            f"where TABLE_NAME = '{table}'")
        output = self.cursor.fetchall()
        self.logger.debug(f"Pull complete, found {str(len(output))} columns for table: {table}")
        for o in output:
            self.tables[table].update({str(o[0]): {'type': str(o[1]), 'size': int(o[2])}})

    def _get_ise_db_schema(self):
        self._get_pubhub_views()
        for t in self.tables.keys():
            self.get_table_columns(t)

    def get_aaa_diagnostics_view(self):
        return self.query_db_table(table='AAA_DIAGNOSTICS_VIEW')

    def get_adapter_status(self):
        return self.query_db_table(table='ADAPTER_STATUS')

    def get_adaptive_network_control(self):
        return self.query_db_table(table='ADAPTIVE_NETWORK_CONTROL')

    def get_administrator_logins(self):
        return self.query_db_table(table='ADMINISTRATOR_LOGINS')

    def get_admin_users(self):
        return self.query_db_table(table='ADMIN_USERS')

    def get_aup_acceptance_status(self):
        return self.query_db_table(table='AUP_ACCEPTANCE_STATUS')

    def get_authorization_profiles(self):
        return self.query_db_table(table='AUTHORIZATION_PROFILES')

    def get_change_configuration_audit(self):
        return self.query_db_table(table='CHANGE_CONFIGURATION_AUDIT')

    def get_coa_events(self):
        return self.query_db_table(table='COA_EVENTS')

    def get_endpoints_data(self):
        return self.query_db_table(table='ENDPOINTS_DATA')

    def get_endpoint_identity_groups(self):
        return self.query_db_table(table='ENDPOINT_IDENTITY_GROUPS')

    def get_endpoint_purge_view(self):
        return self.query_db_table(table='ENDPOINT_PURGE_VIEW')

    def get_ext_id_src_active_directory(self):
        return self.query_db_table(table='EXT_ID_SRC_ACTIVE_DIRECTORY')

    def get_ext_id_src_cert_auth_profile(self):
        return self.query_db_table(table='EXT_ID_SRC_CERT_AUTH_PROFILE')

    def get_ext_id_src_ldap(self):
        return self.query_db_table(table='EXT_ID_SRC_LDAP')

    def get_ext_id_src_odbc(self):
        return self.query_db_table(table='EXT_ID_SRC_ODBC')

    def get_ext_id_src_radius_token(self):
        return self.query_db_table(table='EXT_ID_SRC_RADIUS_TOKEN')

    def get_ext_id_src_rest(self):
        return self.query_db_table(table='EXT_ID_SRC_REST')

    def get_ext_id_src_rsa_securid(self):
        return self.query_db_table(table='EXT_ID_SRC_RSA_SECURID')

    def get_ext_id_src_saml_id_providers(self):
        return self.query_db_table(table='EXT_ID_SRC_SAML_ID_PROVIDERS')

    def get_ext_id_src_social_login(self):
        return self.query_db_table(table='EXT_ID_SRC_SOCIAL_LOGIN')

    def get_failure_code_cause(self):
        return self.query_db_table(table='FAILURE_CODE_CAUSE')

    def get_guest_accounting(self):
        return self.query_db_table(table='GUEST_ACCOUNTING')

    def get_guest_devicelogin_audit(self):
        return self.query_db_table(table='GUEST_DEVICELOGIN_AUDIT')

    def get_key_performance_metrics(self):
        return self.query_db_table(table='KEY_PERFORMANCE_METRICS')

    def get_logical_profiles(self):
        return self.query_db_table(table='LOGICAL_PROFILES')

    def get_misconfigured_nas_view(self):
        return self.query_db_table(table='MISCONFIGURED_NAS_VIEW')

    def get_misconfigured_supplicants_view(self):
        return self.query_db_table(table='MISCONFIGURED_SUPPLICANTS_VIEW')

    def get_network_access_users(self):
        return self.query_db_table(table='NETWORK_ACCESS_USERS')

    def get_network_devices(self):
        return self.query_db_table(table='NETWORK_DEVICES')

    def get_network_device_groups(self):
        return self.query_db_table(table='NETWORK_DEVICE_GROUPS')

    def get_node_list(self):
        return self.query_db_table(table='NODE_LIST')

    def get_openapi_operations(self):
        return self.query_db_table(table='OPENAPI_OPERATIONS')

    def get_policy_sets(self):
        return self.query_db_table(table='POLICY_SETS')

    def get_posture_assessment_by_condition(self):
        return self.query_db_table(table='POSTURE_ASSESSMENT_BY_CONDITION')

    def get_posture_assessment_by_endpoint(self):
        return self.query_db_table(table='POSTURE_ASSESSMENT_BY_ENDPOINT')

    def get_posture_grace_period(self):
        return self.query_db_table(table='POSTURE_GRACE_PERIOD')

    def get_posture_script_condition(self):
        return self.query_db_table(table='POSTURE_SCRIPT_CONDITION')

    def get_posture_script_remediation(self):
        return self.query_db_table(table='POSTURE_SCRIPT_REMEDIATION')

    def get_primary_guest(self):
        return self.query_db_table(table='PRIMARY_GUEST')

    def get_profiled_endpoints_summary(self):
        return self.query_db_table(table='PROFILED_ENDPOINTS_SUMMARY')

    def get_pxgrid_direct_data(self):
        return self.query_db_table(table='PXGRID_DIRECT_DATA')

    def get_radius_accounting(self):
        return self.query_db_table(table='RADIUS_ACCOUNTING')

    def get_radius_accounting_week(self):
        return self.query_db_table(table='RADIUS_ACCOUNTING_WEEK')

    def get_radius_authentications(self):
        return self.query_db_table(table='RADIUS_AUTHENTICATIONS')

    def get_radius_authentications_week(self):
        return self.query_db_table(table='RADIUS_AUTHENTICATIONS_WEEK')

    def get_radius_authentication_summary(self):
        return self.query_db_table(table='RADIUS_AUTHENTICATION_SUMMARY')

    def get_radius_errors_view(self):
        return self.query_db_table(table='RADIUS_ERRORS_VIEW')

    def get_registered_endpoints(self):
        return self.query_db_table(table='REGISTERED_ENDPOINTS')

    def get_security_groups(self):
        return self.query_db_table(table='SECURITY_GROUPS')

    def get_security_group_acls(self):
        return self.query_db_table(table='SECURITY_GROUP_ACLS')

    def get_sponsor_login_and_audit(self):
        return self.query_db_table(table='SPONSOR_LOGIN_AND_AUDIT')

    def get_system_diagnostics_view(self):
        return self.query_db_table(table='SYSTEM_DIAGNOSTICS_VIEW')

    def get_system_summary(self):
        return self.query_db_table(table='SYSTEM_SUMMARY')

    def get_tacacs_accounting(self):
        return self.query_db_table(table='TACACS_ACCOUNTING')

    def get_tacacs_accounting_last_two_days(self):
        return self.query_db_table(table='TACACS_ACCOUNTING_LAST_TWO_DAYS')

    def get_tacacs_authentication(self):
        return self.query_db_table(table='TACACS_AUTHENTICATION')

    def get_tacacs_authentication_last_two_days(self):
        return self.query_db_table(table='TACACS_AUTHENTICATION_LAST_TWO_DAYS')

    def get_tacacs_authentication_summary(self):
        return self.query_db_table(table='TACACS_AUTHENTICATION_SUMMARY')

    def get_tacacs_authorization(self):
        return self.query_db_table(table='TACACS_AUTHORIZATION')

    def get_tacacs_command_accounting(self):
        return self.query_db_table(table='TACACS_COMMAND_ACCOUNTING')

    def get_upspolicy(self):
        return self.query_db_table(table='UPSPOLICY')

    def get_upspolicyset(self):
        return self.query_db_table(table='UPSPOLICYSET')

    def get_upspolicyset_policies(self):
        return self.query_db_table(table='UPSPOLICYSET_POLICIES')

    def get_threat_events(self):
        return self.query_db_table(table='THREAT_EVENTS')

    def get_user_identity_groups(self):
        return self.query_db_table(table='USER_IDENTITY_GROUPS')

    def get_user_password_changes(self):
        return self.query_db_table(table='USER_PASSWORD_CHANGES')

    def get_vulnerability_assessment_failures(self):
        return self.query_db_table(table='VULNERABILITY_ASSESSMENT_FAILURES')

    def reset_db_schema_mapping(self):
        self._get_ise_db_schema()
        schema_writer = open('./schema/tables.json', 'w')
        schema_writer.write(json.dumps(self.tables))
        schema_writer.close()
        self.logger.debug(f"Database schema pulled and written to file")

    def __init__(self, config_path):
        cfg = None
        if config_path:
            with open(config_path, 'r') as stream:
                try:
                    cfg = yaml.safe_load(stream)
                except yaml.YAMLError as exc:
                    print(exc)
                    sys.exit()
        utils = utilities.CFG()
        self.logger = utils.get_logger(log_name='ise-dataconnect.log', log_path=cfg['ise']['log_path'])
        self.logger.debug(f"Initializing database connection to: {cfg['ise']['hostname']}")
        url = "jdbc:oracle:thin:@(DESCRIPTION=(ADDRESS=(PROTOCOL=tcps)" \
              f"(HOST={cfg['ise']['hostname']})(PORT={str(cfg['ise']['port'])}))(CONNECT_DATA=(SID=cpm10)))"
        jvm_path = jpype.getDefaultJVMPath()
        jpype.startJVM(jvm_path, "-Djava.class.path=%s" % cfg['ise']['jar_file_path'],
                       "-Djavax.net.ssl.trustStore=%s" % cfg['ise']['trust_store_path'],
                       "-Djavax.net.ssl.trustStorePassword=%s" % cfg['ise']['trust_store_password'])
        conn = jaydebeapi.connect('oracle.jdbc.driver.OracleDriver',
                                  url,
                                  {'user': 'dataconnect',
                                   'password': cfg['ise']['dataconnect_password'],
                                   'secure': 'true',
                                   'oracle.jdbc.J2EE13Compliant': 'true'},
                                  cfg['ise']['jar_file_path'])
        self.cursor = conn.cursor()
        self.logger.debug(f"Connection to database successful")
        try:
            with open('./schema/tables.json') as schema_reader:
                self.tables = json.loads(schema_reader.read())
                self.logger.debug(f"Pulled database schema from file")
        except:
            self.reset_db_schema_mapping()
            self.logger.debug(f"Unable to pull database schema from file, regenerating now")


if __name__ == '__main__':
    import pprint
    ise = ISEDB('dev_config.yaml')
    ep = ise.query_db("SELECT ENDPOINT_POLICY, MAC_ADDRESS FROM ENDPOINTS_DATA WHERE ENDPOINT_IP = '192.168.200.50'")
    endpoints = ise.get_endpoints_data()
    pprint.pprint(json.dumps(endpoints))
