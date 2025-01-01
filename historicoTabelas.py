hist_tabelas = {
    
    'fulltable' : '''
        CREATE TABLE IF NOT EXISTS full_eventos_wazuh (
            CHAVE                       INTEGER PRIMARY KEY AUTOINCREMENT,
            index                       TEXT NOT NULL,
            id                          TEXT NOT NULL UNIQUE,
            @timestamp                  DATETIME,
            @version                    INTEGER,

            geolocation_area_code       TEXT,
            geolocation_city_name       KEYWORD,
            geolocation_continent_code  TEXT,
            geolocation_coordinates     TEXT,
            geolocation_country_code2   TEXT,
            geolocation_country_code3   TEXT,
            geolocation_dma_code        TEXT,
            geolocation_ip              KEYWORD,
            geolocation_latitude        TEXT,
            geolocation_location        TEXT,
            geolocation_longitude       TEXT,
            geolocation_postal_code     TEXT,
            geolocation_region_name     TEXT,
            geolocation_region_name     TEXT,
            geolocation_timezone        TEXT,

            agent_id                    TEXT,
            agent_ip                    TEXT,
            agent_labels_contrato       KEYWORD,
            agent_labels_group          KEYWORD,
            agent_labels_group2         KEYWORD,
            agent_labels_vm             KEYWORD,
            agent_name                  TEXT,

            cluster_name                KEYWORD,
            cluster_node                KEYWORD,

            command                     KEYWORD,

            data_action                 KEYWORD,
            data_arch                   KEYWORD,
            data_attack                 KEYWORD,
            data_attackid               KEYWORD,
            data_audit_acct             KEYWORD,
            data_audit_arch             KEYWORD,
            data_audit_auid             KEYWORD,
            data_audit_command          KEYWORD,
            data_audit_cwd              KEYWORD,
            data_audit_dev              KEYWORD,
            data_audit_directory_inode  KEYWORD,
            data_audit_directory_mode   KEYWORD,
            data_audit_directory_name   KEYWORD,
            data_audit_egid             KEYWORD,
            data_audit_enforcing        KEYWORD,
            data_audit_euid             KEYWORD,
            data_audit_exe              KEYWORD,
            data_audit_execve_a0        KEYWORD,
            data_audit_execve_a1        KEYWORD,
            data_audit_execve_a2        KEYWORD,
            data_audit_execve_a3        KEYWORD,
            data_audit_exit             KEYWORD,
            data_audit_file_inode       KEYWORD,
            data_audit_file_mode        KEYWORD,
            data_audit_file_name        KEYWORD,
            data_audit_fsgid            KEYWORD,
            data_audit_fsuid            KEYWORD,
            data_audit_gid              KEYWORD,
            data_audit_id               KEYWORD,
            data_audit_key              KEYWORD,
            data_audit_list             KEYWORD,
            data_audit_old-auid         KEYWORD,
            data_audit_old-ses          KEYWORD,
            data_audit_old_enforcing    KEYWORD,
            data_audit_old_prom         KEYWORD,
            data_audit_op               KEYWORD,
            data_audit_pid              KEYWORD,
            data_audit_ppid             KEYWORD,
            data_audit_prom             KEYWORD,
            data_audit_res              KEYWORD,
            data_audit_session          KEYWORD,
            data_audit_sgid             KEYWORD,
            data_audit_srcip            KEYWORD,
            data_audit_subj             KEYWORD,
            data_audit_sucess           KEYWORD,
            data_audit_suid             KEYWORD,
            data_audit_syscall          KEYWORD,
            data_audit_tty              KEYWORD,
            data_audit_type             KEYWORD,
            data_audit_uid              KEYWORD,
            data_aws_account_id         KEYWORD,
            data_aws_bytes              KEYWORD,
            data_aws_createdAt          DATETIME,
            data_aws_dstaddr            KEYWORD,
            data_aws_end                DATETIME,
            data_aws_log_info_s3bucket  KEYWORD,
            data_aws_region             KEYWORD,
            data_aws_resource_instanceDetails_launchTime                                DATETIME,
            data_aws_resource_instanceDetails_networkInterfaces_privateIpAddress        KEYWORD,
            data_aws_resource_instanceDetails_networkInterfaces_publicIp                KEYWORD,
            data_aws_service_action_networkConnectionAction_remoteIpDetails_geolocation KEYWORD,
            data_aws_service_action_networkConnectionAction_remoteIpDetails_ipAdressV4  KEYWORD,
            data_aws_service_action_count                                               KEYWORD,
            data_aws_service_action_eventFirstSeen                                      DATETIME,
            data_aws_service_action_eventLastSeen                                       DATETIME,
            data_aws_source                     KEYWORD,
            data_aws_source_ip_address          KEYWORD,
            data_aws_srcaddr                    KEYWORD,
            data_aws_start                      DATETIME,
            data_aws_updatedAt                  DATETIME,
            data_cis_benchmark                  KEYWORD,
            data_cis_error                      KEYWORD,
            data_cis_fail                       KEYWORD,
            data_cis_group                      KEYWORD,
            data_cis_notchecked                 KEYWORD,
            data_cis_pass                       KEYWORD,
            data_cis_result                     KEYWORD,
            data_cis_rule_title                 KEYWORD,
            data_cis_score                      KEYWORD,
            data_cis_timestamp                  KEYWORD,
            data_cis_unknown                    KEYWORD,
            data_command                        KEYWORD,
            data_craction                       KEYWORD,
            data_crlevel                        KEYWORD,
            data_crscore                        KEYWORD,
            data_data                           KEYWORD,
            data_datacenter                     KEYWORD,
            data_devid                          KEYWORD,
            data_devname                        KEYWORD,
            data_direction                      KEYWORD,
            data_docker_action                  KEYWORD,
            data_docker_actor_attributes_image  KEYWORD,
            data_docker_actor_attributes_name   KEYWORD,
            data_docker_actor_type              KEYWORD,
            data_dpkg_status                    KEYWORD,
            data_dstintf                        KEYWORD,
            data_dstintfrole                    KEYWORD,
            data_dstip                          KEYWORD,
            data_dstport                        KEYWORD,
            data_dstuser                        KEYWORD,
            data_esxi_host                      KEYWORD,
            data_event_id                       KEYWORD,
            data_eventtime                      KEYWORD,
            data_eventtype                      KEYWORD,
            data_extra_data                     KEYWORD,
            data_file                           KEYWORD,
            data_gcp_jsonPayload_authAnswer     KEYWORD, 
            data_gcp_jsonPayload_queryName      KEYWORD,
            data_gcp_jsonPayload_responseCode   KEYWORD,
            data_gcp_jsonPayload_vmInstanceId   KEYWORD,
            data_gcp_jsonPayload_vmInstanceName KEYWORD,
            
        )
    ''',
    
    'reducedTable' :  '''
        CREATE TABLE wazuh_events (
            chave INT AUTO_INCREMENT PRIMARY KEY,
            index TEXT NOT NULL, 
            id TEXT NOT NULL UNIQUE,
            @timestamp DATETIME,
            agent_id VARCHAR(255),
            agent_ip VARCHAR(255),
            agent_labels_contrato VARCHAR(255),
            agent_labels_group VARCHAR(255),
            agent_labels_group2 VARCHAR(255),
            agent_labels_vm VARCHAR(255),
            agent_name VARCHAR(255),
            data_data VARCHAR(255),
            data_dstip VARCHAR(255),
            data_dstport VARCHAR(255),
            data_dstuser VARCHAR(255),
            data_id VARCHAR(255),
            data_os_architecture VARCHAR(255),
            data_os_build VARCHAR(255),
            data_os_codename VARCHAR(255),
            data_os_display_version VARCHAR(255),
            data_os_hostname VARCHAR(255),
            data_os_major VARCHAR(255),
            data_os_minor VARCHAR(255),
            data_os_name VARCHAR(255),
            data_os_patch VARCHAR(255),
            data_os_platform VARCHAR(255),
            data_os_release VARCHAR(255),
            data_os_release_version VARCHAR(255),
            data_os_sysname VARCHAR(255),
            data_os_version VARCHAR(255),
            data_port_inode INT,
            data_port_local_ip TEXT,
            data_port_local_port INT,
            data_port_pid INT,
            data_port_process VARCHAR(255),
            data_port_protocol VARCHAR(255),
            data_port_remote_ip TEXT,
            data_port_remote_port INT,
            data_port_rx_queue INT,
            data_port_state VARCHAR(255),
            data_port_tx_queue INT,

            data_process_args VARCHAR(255),
            data_process_cmd VARCHAR(255),
            data_process_egroup VARCHAR(255),
            data_process_euser VARCHAR(255),
            data_process_fgroup VARCHAR(255),
            data_process_name VARCHAR(255),
            data_process_nice INT,
            data_process_nlwp INT,
            data_process_pgrp INT,
            data_process_pid INT,
            data_process_ppid INT,
            data_process_priority INT,
            data_process_processor INT,
            data_process_resident INT,
            data_process_rgroup VARCHAR(255),
            data_process_ruser VARCHAR(255),
            data_process_session INT,
            data_process_sgroup VARCHAR(255),
            data_process_share INT,
            data_process_size INT,
            data_process_start_time INT,
            data_process_state VARCHAR(255),
            data_process_stime INT,
            data_process_suser VARCHAR(255),
            data_process_tgid INT,
            data_process_tty INT,
            data_process_utime INT,
            data_process_vm_size INT,

            data_protocol VARCHAR(255),
            data_srcip VARCHAR(255),
            data_srcport VARCHAR(255),
            data_status VARCHAR(255),
            data_title VARCHAR(255),
            data_type VARCHAR(255),
            data_uid VARCHAR(255),

            data_virustotal_description VARCHAR(255),
            data_virustotal_error VARCHAR(255),
            data_virustotal_found VARCHAR(255),
            data_virustotal_malicious VARCHAR(255),
            data_virustotal_permalink VARCHAR(255),
            data_virustotal_positives VARCHAR(255),
            data_virustotal_scan_date VARCHAR(255),
            data_virustotal_sha1 VARCHAR(255),
            data_virustotal_source_alert_id VARCHAR(255),
            data_virustotal_source_file VARCHAR(255),
            data_virustotal_source_md5 VARCHAR(255),
            data_virustotal_source_sha1 VARCHAR(255),
            data_virustotal_total VARCHAR(255),

            data_vulnerability_assigner VARCHAR(255),
            data_vulnerability_bugzilla_references VARCHAR(255),
            data_vulnerability_cve VARCHAR(255),
            data_vulnerability_cve_version VARCHAR(255),

            data_vulnerability_cvss_cvss2_base_score VARCHAR(255),
            data_vulnerability_cvss_cvss2_exploitability_score VARCHAR(255),
            data_vulnerability_cvss_cvss2_impact_score VARCHAR(255),

            data_vulnerability_cvss_cvss2_vector_access_complexity VARCHAR(255),
            data_vulnerability_cvss_cvss2_vector_attack_vector VARCHAR(255),
            data_vulnerability_cvss_cvss2_vector_authentication VARCHAR(255),
            data_vulnerability_cvss_cvss2_vector_availability VARCHAR(255),
            data_vulnerability_cvss_cvss2_vector_confidentiality_impact VARCHAR(255),
            data_vulnerability_cvss_cvss2_vector_integrity_impact VARCHAR(255),
            data_vulnerability_cvss_cvss2_vector_privileges_required VARCHAR(255),
            data_vulnerability_cvss_cvss2_vector_scope VARCHAR(255),
            data_vulnerability_cvss_cvss2_vector_user_interaction VARCHAR(255),

            data_vulnerability_cvss_cvss3_base_score VARCHAR(255),
            data_vulnerability_cvss_cvss3_exploitability_score VARCHAR(255),
            data_vulnerability_cvss_cvss3_impact_score VARCHAR(255),
            data_vulnerability_cvss_cvss3_vector_access_complexity VARCHAR(255),
            data_vulnerability_cvss_cvss3_vector_attack_vector VARCHAR(255),
            data_vulnerability_cvss_cvss3_vector_authentication VARCHAR(255),
            data_vulnerability_cvss_cvss3_vector_availability VARCHAR(255),
            data_vulnerability_cvss_cvss3_vector_confidentiality_impact VARCHAR(255),
            data_vulnerability_cvss_cvss3_vector_integrity_impact VARCHAR(255),
            data_vulnerability_cvss_cvss3_vector_privileges_required VARCHAR(255),
            data_vulnerability_cvss_cvss3_vector_scope VARCHAR(255),
            data_vulnerability_cvss_cvss3_vector_user_interaction VARCHAR(255),

            data_vulnerability_cwe_reference VARCHAR(255),

            data_vulnerability_package_architecture VARCHAR(255),
            data_vulnerability_package_condition VARCHAR(255),
            data_vulnerability_package_generated_cpe VARCHAR(255),
            data_vulnerability_package_name VARCHAR(255),
            data_vulnerability_package_source VARCHAR(255),
            data_vulnerability_package_version VARCHAR(255),
            
            data_vulnerability_published DATETIME,
            data_vulnerability_rationale VARCHAR(255),
            data_vulnerability_references VARCHAR(255),
            data_vulnerability_severity VARCHAR(255),
            data_vulnerability_status VARCHAR(255),
            data_vulnerability_title VARCHAR(255),
            data_vulnerability_type VARCHAR(255),
            data_vulnerability_updated DATETIME
        )
    ''',

    'finalTableScheme' : '''
        CREATE OR REPLACE TABLE `Wazuh_Events` (
            `chave` INTEGER NOT NULL AUTO_INCREMENT UNIQUE,
            `index` TEXT(65535) NOT NULL,
            `timestamp` DATETIME NOT NULL,
            `Agent` INTEGER,
            `data` INTEGER,
            PRIMARY KEY(`chave`)
        );

        CREATE OR REPLACE TABLE `Agent` (
            `chave` INTEGER NOT NULL AUTO_INCREMENT UNIQUE,
            `id` VARCHAR(255),
            `ip` VARCHAR(255),
            `labels` INTEGER,
            `name` VARCHAR(255),
            PRIMARY KEY(`chave`)
        );

        CREATE OR REPLACE TABLE `Labels` (
            `chave` INTEGER NOT NULL AUTO_INCREMENT UNIQUE,
            `contrato` VARCHAR(255),
            `group` VARCHAR(255),
            `group2` VARCHAR(255),
            `vm` VARCHAR(255),
            PRIMARY KEY(`chave`)
        );

        CREATE INDEX `Labels_index_0`
        ON `Labels` (`chave`);
        CREATE OR REPLACE TABLE `Data` (
            `chave` INTEGER NOT NULL AUTO_INCREMENT UNIQUE,
            `data` VARCHAR(255),
            `dstport` VARCHAR(255),
            `dstip` VARCHAR(255),
            `dstuser` VARCHAR(255),
            `id` VARCHAR(255),
            `os` INTEGER,
            `port` INTEGER,
            `process` INTEGER,
            `protocol` VARCHAR(255),
            `srcip` VARCHAR(255),
            `srcport` VARCHAR(255),
            `status` VARCHAR(255),
            `title` VARCHAR(255),
            `type` VARCHAR(255),
            `uid` VARCHAR(255),
            `vulnerability` INTEGER,
            `virustotal` INTEGER,
            PRIMARY KEY(`chave`)
        );

        CREATE OR REPLACE TABLE `Process` (
            `chave` INTEGER NOT NULL AUTO_INCREMENT UNIQUE,
            `args` VARCHAR(255),
            `cmd` VARCHAR(255),
            `egroup` VARCHAR(255),
            `euser` VARCHAR(255),
            `fgroup` VARCHAR(255),
            `name` VARCHAR(255),
            `nice` INTEGER,
            `nlwp` INTEGER,
            `pgrp` INTEGER,
            `pid` INTEGER,
            `ppid` INTEGER,
            `priority` INTEGER,
            `processor` INTEGER,
            `resident` INTEGER,
            `rgroup` VARCHAR(255),
            `ruser` VARCHAR(255),
            `session` INTEGER,
            `sgroup` VARCHAR(255),
            `share` INTEGER,
            `size` INTEGER,
            `start_time` INTEGER,
            `state` VARCHAR(255),
            `stime` INTEGER,
            `suser` VARCHAR(255),
            `tgid` INTEGER,
            `tty` INTEGER,
            `utime` INTEGER,
            `vm_size` INTEGER,
            PRIMARY KEY(`chave`)
        );

        CREATE OR REPLACE TABLE `Os` (
            `chave` INTEGER NOT NULL AUTO_INCREMENT UNIQUE,
            `architecture` VARCHAR(255),
            `hostname` VARCHAR(255),
            `name` VARCHAR(255),
            `version` VARCHAR(255),
            PRIMARY KEY(`chave`)
        );

        CREATE OR REPLACE TABLE `Port` (
            `chave` INTEGER NOT NULL AUTO_INCREMENT UNIQUE,
            `inode` INTEGER,
            `local_ip` TEXT(65535),
            `local_port` INTEGER,
            `pid` INTEGER,
            `process` VARCHAR(255),
            `protocol` VARCHAR(255),
            `remote_ip` TEXT(65535),
            `remote_port` INTEGER,
            `rx_queue` INTEGER,
            `state` VARCHAR(255),
            `tx_queue` INTEGER,
            PRIMARY KEY(`chave`)
        );

        CREATE OR REPLACE TABLE `Vulnerability` (
            `chave` INTEGER NOT NULL AUTO_INCREMENT UNIQUE,
            `advisories_ids` VARCHAR(255),
            `assigner` VARCHAR(255),
            `bugzilla_references` VARCHAR(255),
            `cve` VARCHAR(255),
            `cvss` INTEGER,
            `package` INTEGER,
            `published` DATETIME,
            `rationale` VARCHAR(255),
            `references` VARCHAR(255),
            `severity` VARCHAR(255),
            `status` VARCHAR(255),
            `title` VARCHAR(255),
            `type` VARCHAR(255),
            `updated` DATETIME,
            `cwe_reference` VARCHAR(255),
            PRIMARY KEY(`chave`)
        );

        CREATE OR REPLACE TABLE `virustotal` (
            `chave` INTEGER NOT NULL AUTO_INCREMENT UNIQUE,
            `description` VARCHAR(255),
            `error` VARCHAR(255),
            `found` VARCHAR(255),
            `malicious` VARCHAR(255),
            `permalink` VARCHAR(255),
            `positives` VARCHAR(255),
            `scan_date` VARCHAR(255),
            `sha1` VARCHAR(255),
            `source` INTEGER,
            `total` VARCHAR(255),
            PRIMARY KEY(`chave`)
        );

        CREATE OR REPLACE TABLE `Cvss` (
            `chave` INTEGER NOT NULL AUTO_INCREMENT UNIQUE,
            `cvss2` INTEGER,
            `cvss3` INTEGER,
            PRIMARY KEY(`chave`)
        );

        CREATE OR REPLACE TABLE `Package` (
            `chave` INTEGER NOT NULL AUTO_INCREMENT UNIQUE,
            `architecture` VARCHAR(255),
            `condition` VARCHAR(255),
            `name` VARCHAR(255),
            `source` VARCHAR(255),
            `version` VARCHAR(255),
            PRIMARY KEY(`chave`)
        );

        CREATE OR REPLACE TABLE `Cvss_Cvss` (
            `chave` INTEGER NOT NULL AUTO_INCREMENT UNIQUE,
            `base_score` VARCHAR(255),
            `exploitability_score` VARCHAR(255),
            `impact_score` VARCHAR(255),
            `vector` INTEGER,
            PRIMARY KEY(`chave`)
        );

        CREATE OR REPLACE TABLE `Vector` (
            `chave` INTEGER NOT NULL AUTO_INCREMENT UNIQUE,
            `access_complexity` VARCHAR(255),
            `attack_vector` VARCHAR(255),
            `authentication` VARCHAR(255),
            `availability` VARCHAR(255),
            `confidentiality_impact` VARCHAR(255),
            `integrity_impact` VARCHAR(255),
            `privileges_required` VARCHAR(255),
            `scope` VARCHAR(255),
            `user_interaction` VARCHAR(255),
            PRIMARY KEY(`chave`)
        );

        CREATE OR REPLACE TABLE `Source` (
            `chave` INTEGER NOT NULL AUTO_INCREMENT UNIQUE,
            `alert_id` VARCHAR(255),
            `file` VARCHAR(255),
            `md5` VARCHAR(255),
            `sha1` VARCHAR(255),
            PRIMARY KEY(`chave`)
        );

        ALTER TABLE `Agent`
        ADD FOREIGN KEY(`labels`) REFERENCES `Labels`(`chave`)
        ON UPDATE NO ACTION ON DELETE NO ACTION;
        ALTER TABLE `Wazuh_Events`
        ADD FOREIGN KEY(`Agent`) REFERENCES `Agent`(`chave`)
        ON UPDATE NO ACTION ON DELETE NO ACTION;
        ALTER TABLE `Wazuh_Events`
        ADD FOREIGN KEY(`data`) REFERENCES `Data`(`chave`)
        ON UPDATE NO ACTION ON DELETE NO ACTION;
        ALTER TABLE `Data`
        ADD FOREIGN KEY(`process`) REFERENCES `Process`(`chave`)
        ON UPDATE NO ACTION ON DELETE NO ACTION;
        ALTER TABLE `Data`
        ADD FOREIGN KEY(`vulnerability`) REFERENCES `Vulnerability`(`chave`)
        ON UPDATE NO ACTION ON DELETE NO ACTION;
        ALTER TABLE `Vulnerability`
        ADD FOREIGN KEY(`cvss`) REFERENCES `Cvss`(`chave`)
        ON UPDATE NO ACTION ON DELETE NO ACTION;
        ALTER TABLE `Cvss`
        ADD FOREIGN KEY(`cvss2`) REFERENCES `Cvss_Cvss`(`chave`)
        ON UPDATE NO ACTION ON DELETE NO ACTION;
        ALTER TABLE `Cvss`
        ADD FOREIGN KEY(`cvss3`) REFERENCES `Cvss_Cvss`(`chave`)
        ON UPDATE NO ACTION ON DELETE NO ACTION;
        ALTER TABLE `Vulnerability`
        ADD FOREIGN KEY(`package`) REFERENCES `Package`(`chave`)
        ON UPDATE NO ACTION ON DELETE NO ACTION;
        ALTER TABLE `Cvss_Cvss`
        ADD FOREIGN KEY(`vector`) REFERENCES `Vector`(`chave`)
        ON UPDATE NO ACTION ON DELETE NO ACTION;
        ALTER TABLE `Data`
        ADD FOREIGN KEY(`os`) REFERENCES `Os`(`chave`)
        ON UPDATE NO ACTION ON DELETE NO ACTION;
        ALTER TABLE `Data`
        ADD FOREIGN KEY(`port`) REFERENCES `Port`(`chave`)
        ON UPDATE NO ACTION ON DELETE NO ACTION;
        ALTER TABLE `Data`
        ADD FOREIGN KEY(`virustotal`) REFERENCES `virustotal`(`chave`)
        ON UPDATE NO ACTION ON DELETE NO ACTION;
        ALTER TABLE `virustotal`
        ADD FOREIGN KEY(`source`) REFERENCES `Source`(`chave`)
        ON UPDATE NO ACTION ON DELETE NO ACTION;
    ''',

    'finalTables':{
        [('agent', 'CREATE TABLE `agent` (\n  `chave` int(11) NOT NULL AUTO_INCREMENT,\n  `id` varchar(255) DEFAULT NULL,\n  `ip` varchar(255) DEFAULT NULL,\n  `labels` int(11) DEFAULT NULL,\n  `name` varchar(255) DEFAULT NULL,\n  PRIMARY KEY (`chave`),\n  UNIQUE KEY `key` (`chave`),\n  KEY `labels` (`labels`),\n  CONSTRAINT `agent_ibfk_1` FOREIGN KEY (`labels`) REFERENCES `labels` (`chave`) ON DELETE NO ACTION ON UPDATE NO ACTION\n) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin')]
        [('cvss', 'CREATE TABLE `cvss` (\n  `chave` int(11) NOT NULL AUTO_INCREMENT,\n  `cvss2` int(11) DEFAULT NULL,\n  `cvss3` int(11) DEFAULT NULL,\n  PRIMARY KEY (`chave`),\n  UNIQUE KEY `key` (`chave`),\n  KEY `cvss2` (`cvss2`),\n  KEY `cvss3` (`cvss3`),\n  CONSTRAINT `cvss_ibfk_1` FOREIGN KEY (`cvss2`) REFERENCES `cvss_cvss` (`chave`) ON DELETE NO ACTION ON UPDATE NO ACTION,\n  CONSTRAINT `cvss_ibfk_2` FOREIGN KEY (`cvss3`) REFERENCES `cvss_cvss` (`chave`) ON DELETE NO ACTION ON UPDATE NO ACTION\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin')]
        [('cvss_cvss', 'CREATE TABLE `cvss_cvss` (\n  `chave` int(11) NOT NULL AUTO_INCREMENT,\n  `base_score` varchar(255) DEFAULT NULL,\n  `exploitability_score` varchar(255) DEFAULT NULL,\n  `impact_score` varchar(255) DEFAULT NULL,\n  `vector` int(11) DEFAULT NULL,\n  PRIMARY KEY (`chave`),\n  UNIQUE KEY `key` (`chave`),\n  KEY `vector` (`vector`),\n  CONSTRAINT `cvss_cvss_ibfk_1` FOREIGN KEY (`vector`) REFERENCES `vector` (`chave`) ON DELETE NO ACTION ON UPDATE NO ACTION\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin')]
        [('data', 'CREATE TABLE `data` (\n  `chave` int(11) NOT NULL AUTO_INCREMENT,\n  `data` varchar(255) DEFAULT NULL,\n  `dstport` varchar(255) DEFAULT NULL,\n  `dstip` varchar(255) DEFAULT NULL,\n  `dstuser` varchar(255) DEFAULT NULL,\n  `id` varchar(255) DEFAULT NULL,\n  `os` int(11) DEFAULT NULL,\n  `port` int(11) DEFAULT NULL,\n  `process` int(11) DEFAULT NULL,\n  `protocol` varchar(255) DEFAULT NULL,\n  `srcip` varchar(255) DEFAULT NULL,\n  `srcport` varchar(255) DEFAULT NULL,\n  `status` varchar(255) DEFAULT NULL,\n  `title` varchar(255) DEFAULT NULL,\n  `type` varchar(255) DEFAULT NULL,\n  `uid` varchar(255) DEFAULT NULL,\n  `vulnerability` int(11) DEFAULT NULL,\n  `virustotal` int(11) DEFAULT NULL,\n  PRIMARY KEY (`chave`),\n  UNIQUE KEY `key` (`chave`),\n  KEY `process` (`process`),\n  KEY `vulnerability` (`vulnerability`),\n  KEY `os` (`os`),\n  KEY `port` (`port`),\n  KEY `virustotal` (`virustotal`),\n  CONSTRAINT `data_ibfk_1` FOREIGN KEY (`process`) REFERENCES `process` (`chave`) ON DELETE NO ACTION ON UPDATE NO ACTION,\n  CONSTRAINT `data_ibfk_2` FOREIGN KEY (`vulnerability`) REFERENCES `vulnerability` (`chave`) ON DELETE NO ACTION ON UPDATE NO ACTION,\n  CONSTRAINT `data_ibfk_3` FOREIGN KEY (`os`) REFERENCES `os` (`chave`) ON DELETE NO ACTION ON UPDATE NO ACTION,\n  CONSTRAINT `data_ibfk_4` FOREIGN KEY (`port`) REFERENCES `port` (`chave`) ON DELETE NO ACTION ON UPDATE NO ACTION,\n  CONSTRAINT `data_ibfk_5` FOREIGN KEY (`virustotal`) REFERENCES `virustotal` (`chave`) ON DELETE NO ACTION ON UPDATE NO ACTION\n) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin')]
        [('labels', 'CREATE TABLE `labels` (\n  `chave` int(11) NOT NULL AUTO_INCREMENT,\n  `contrato` varchar(255) DEFAULT NULL,\n  `group` varchar(255) DEFAULT NULL,\n  `group2` varchar(255) DEFAULT NULL,\n  `vm` varchar(255) DEFAULT NULL,\n  PRIMARY KEY (`chave`),\n  UNIQUE KEY `key` (`chave`),\n  KEY `Labels_index_0` (`chave`)\n) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin')]
        [('os', 'CREATE TABLE `os` (\n  `chave` int(11) NOT NULL AUTO_INCREMENT,\n  `architecture` varchar(255) DEFAULT NULL,\n  `hostname` varchar(255) DEFAULT NULL,\n  `name` varchar(255) DEFAULT NULL,\n  `version` varchar(255) DEFAULT NULL,\n  PRIMARY KEY (`chave`),\n  UNIQUE KEY `key` (`chave`)\n) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin')]
        [('package', 'CREATE TABLE `package` (\n  `chave` int(11) NOT NULL AUTO_INCREMENT,\n  `architecture` varchar(255) DEFAULT NULL,\n  `condition` varchar(255) DEFAULT NULL,\n  `name` varchar(255) DEFAULT NULL,\n  `source` varchar(255) DEFAULT NULL,\n  `version` varchar(255) DEFAULT NULL,\n  PRIMARY KEY (`chave`),\n  UNIQUE KEY `key` (`chave`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin')]
        [('port', 'CREATE TABLE `port` (\n  `chave` int(11) NOT NULL AUTO_INCREMENT,\n  `inode` int(11) DEFAULT NULL,\n  `local_ip` mediumtext DEFAULT NULL,\n  `local_port` int(11) DEFAULT NULL,\n  `pid` int(11) DEFAULT NULL,\n  `process` varchar(255) DEFAULT NULL,\n  `protocol` varchar(255) DEFAULT NULL,\n  `remote_ip` mediumtext DEFAULT NULL,\n  `remote_port` int(11) DEFAULT NULL,\n  `rx_queue` int(11) DEFAULT NULL,\n  `state` varchar(255) DEFAULT NULL,\n  `tx_queue` int(11) DEFAULT NULL,\n  PRIMARY KEY (`chave`),\n  UNIQUE KEY `key` (`chave`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin')]
        [('process', 'CREATE TABLE `process` (\n  `chave` int(11) NOT NULL AUTO_INCREMENT,\n  `args` varchar(255) DEFAULT NULL,\n  `cmd` varchar(255) DEFAULT NULL,\n  `egroup` varchar(255) DEFAULT NULL,\n  `euser` varchar(255) DEFAULT NULL,\n  `fgroup` varchar(255) DEFAULT NULL,\n  `name` varchar(255) DEFAULT NULL,\n  `nice` int(11) DEFAULT NULL,\n  `nlwp` int(11) DEFAULT NULL,\n  `pgrp` int(11) DEFAULT NULL,\n  `pid` int(11) DEFAULT NULL,\n  `ppid` int(11) DEFAULT NULL,\n  `priority` int(11) DEFAULT NULL,\n  `processor` int(11) DEFAULT NULL,\n  `resident` int(11) DEFAULT NULL,\n  `rgroup` varchar(255) DEFAULT NULL,\n  `ruser` varchar(255) DEFAULT NULL,\n  `session` int(11) DEFAULT NULL,\n  `sgroup` varchar(255) DEFAULT NULL,\n  `share` int(11) DEFAULT NULL,\n  `size` int(11) DEFAULT NULL,\n  `start_time` int(11) DEFAULT NULL,\n  `state` varchar(255) DEFAULT NULL,\n  `stime` int(11) DEFAULT NULL,\n  `suser` varchar(255) DEFAULT NULL,\n  `tgid` int(11) DEFAULT NULL,\n  `tty` int(11) DEFAULT NULL,\n  `utime` int(11) DEFAULT NULL,\n  `vm_size` int(11) DEFAULT NULL,\n  PRIMARY KEY (`chave`),\n  UNIQUE KEY `key` (`chave`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin')]
        [('source', 'CREATE TABLE `source` (\n  `chave` int(11) NOT NULL AUTO_INCREMENT,\n  `alert_id` varchar(255) DEFAULT NULL,\n  `file` varchar(255) DEFAULT NULL,\n  `md5` varchar(255) DEFAULT NULL,\n  `sha1` varchar(255) DEFAULT NULL,\n  PRIMARY KEY (`chave`),\n  UNIQUE KEY `key` (`chave`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin')]
        [('vector', 'CREATE TABLE `vector` (\n  `chave` int(11) NOT NULL AUTO_INCREMENT,\n  `access_complexity` varchar(255) DEFAULT NULL,\n  `attack_vector` varchar(255) DEFAULT NULL,\n  `authentication` varchar(255) DEFAULT NULL,\n  `availability` varchar(255) DEFAULT NULL,\n  `confidentiality_impact` varchar(255) DEFAULT NULL,\n  `integrity_impact` varchar(255) DEFAULT NULL,\n  `privileges_required` varchar(255) DEFAULT NULL,\n  `scope` varchar(255) DEFAULT NULL,\n  `user_interaction` varchar(255) DEFAULT NULL,\n  PRIMARY KEY (`chave`),\n  UNIQUE KEY `key` (`chave`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin')]
        [('virustotal', 'CREATE TABLE `virustotal` (\n  `chave` int(11) NOT NULL AUTO_INCREMENT,\n  `description` varchar(255) DEFAULT NULL,\n  `error` varchar(255) DEFAULT NULL,\n  `found` varchar(255) DEFAULT NULL,\n  `malicious` varchar(255) DEFAULT NULL,\n  `permalink` varchar(255) DEFAULT NULL,\n  `positives` varchar(255) DEFAULT NULL,\n  `scan_date` varchar(255) DEFAULT NULL,\n  `sha1` varchar(255) DEFAULT NULL,\n  `source` int(11) DEFAULT NULL,\n  `total` varchar(255) DEFAULT NULL,\n  PRIMARY KEY (`chave`),\n  UNIQUE KEY `key` (`chave`),\n  KEY `source` (`source`),\n  CONSTRAINT `virustotal_ibfk_1` FOREIGN KEY (`source`) REFERENCES `source` (`chave`) ON DELETE NO ACTION ON UPDATE NO ACTION\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin')]
        [('vulnerability', 'CREATE TABLE `vulnerability` (\n  `chave` int(11) NOT NULL AUTO_INCREMENT,\n  `advisories_ids` varchar(255) DEFAULT NULL,\n  `assigner` varchar(255) DEFAULT NULL,\n  `bugzilla_references` varchar(255) DEFAULT NULL,\n  `cve` varchar(255) DEFAULT NULL,\n  `cvss` int(11) DEFAULT NULL,\n  `package` int(11) DEFAULT NULL,\n  `published` datetime DEFAULT NULL,\n  `rationale` varchar(255) DEFAULT NULL,\n  `references` varchar(255) DEFAULT NULL,\n  `severity` varchar(255) DEFAULT NULL,\n  `status` varchar(255) DEFAULT NULL,\n  `title` varchar(255) DEFAULT NULL,\n  `type` varchar(255) DEFAULT NULL,\n  `updated` datetime DEFAULT NULL,\n  `cwe_reference` varchar(255) DEFAULT NULL,\n  PRIMARY KEY (`chave`),\n  UNIQUE KEY `key` (`chave`),\n  KEY `cvss` (`cvss`),\n  KEY `package` (`package`),\n  CONSTRAINT `vulnerability_ibfk_1` FOREIGN KEY (`cvss`) REFERENCES `cvss` (`chave`) ON DELETE NO ACTION ON UPDATE NO ACTION,\n  CONSTRAINT `vulnerability_ibfk_2` FOREIGN KEY (`package`) REFERENCES `package` (`chave`) ON DELETE NO ACTION ON UPDATE NO ACTION\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin')]
        [('wazuh_events', 'CREATE TABLE `wazuh_events` (\n  `chave` int(11) NOT NULL AUTO_INCREMENT,\n  `idx` mediumtext NOT NULL,\n  `id` varchar(255) NOT NULL,\n  `timestamp` datetime NOT NULL,\n  `Agent` int(11) DEFAULT NULL,\n  `data` int(11) DEFAULT NULL,\n  PRIMARY KEY (`chave`),\n  UNIQUE KEY `key` (`chave`),\n  KEY `Agent` (`Agent`),\n  KEY `data` (`data`),\n  CONSTRAINT `wazuh_events_ibfk_1` FOREIGN KEY (`Agent`) REFERENCES `agent` (`chave`) ON DELETE NO ACTION ON UPDATE NO ACTION,\n  CONSTRAINT `wazuh_events_ibfk_2` FOREIGN KEY (`data`) REFERENCES `data` (`chave`) ON DELETE NO ACTION ON UPDATE NO ACTION\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin')]
    },
    'link' : 'https://www.drawdb.app/editor?shareId=bc4419de656107e61a2ddbfeee9eaba7'
}