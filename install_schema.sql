
/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
DROP TABLE IF EXISTS `agent_provisioning`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `agent_provisioning` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `organisation_id` int unsigned DEFAULT NULL,
  `tag_name` varchar(191) NOT NULL,
  `qualys_tag_id` bigint unsigned DEFAULT NULL,
  `activation_key_id` bigint unsigned DEFAULT NULL,
  `activation_key` char(36) DEFAULT NULL,
  `local_tag_id` int unsigned DEFAULT NULL,
  `status` enum('in_progress','complete') NOT NULL DEFAULT 'in_progress',
  `last_error` text,
  `created_by` int unsigned DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `completed_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_agent_prov_tag_name` (`tag_name`),
  UNIQUE KEY `uq_agent_prov_org` (`organisation_id`),
  UNIQUE KEY `uq_agent_prov_qualys_tag` (`qualys_tag_id`),
  UNIQUE KEY `uq_agent_prov_key_id` (`activation_key_id`),
  UNIQUE KEY `uq_agent_prov_key` (`activation_key`),
  UNIQUE KEY `uq_agent_prov_local_tag` (`local_tag_id`),
  KEY `fk_agent_prov_user` (`created_by`),
  CONSTRAINT `fk_agent_prov_local_tag` FOREIGN KEY (`local_tag_id`) REFERENCES `tags` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_agent_prov_org` FOREIGN KEY (`organisation_id`) REFERENCES `organisations` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_agent_prov_user` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `agent_uninstall_queue`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `agent_uninstall_queue` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `asset_id` int unsigned DEFAULT NULL,
  `qualys_host_id` bigint unsigned NOT NULL,
  `qualys_asset_id` bigint unsigned DEFAULT NULL,
  `hostname` varchar(255) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `status` enum('pending','processing','uninstalled','failed') NOT NULL DEFAULT 'pending',
  `requested_by` int unsigned DEFAULT NULL,
  `requested_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `processed_at` datetime DEFAULT NULL,
  `attempts` int unsigned NOT NULL DEFAULT '0',
  `last_error` text,
  `active_dedup` bigint unsigned GENERATED ALWAYS AS ((case when (`status` in (_utf8mb4'pending',_utf8mb4'processing')) then `qualys_host_id` else NULL end)) STORED,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_uninstall_active_host` (`active_dedup`),
  KEY `fk_uninstall_user` (`requested_by`),
  KEY `idx_uninstall_status` (`status`),
  KEY `idx_uninstall_asset` (`asset_id`),
  CONSTRAINT `fk_uninstall_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_uninstall_user` FOREIGN KEY (`requested_by`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=66 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `asset_tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `asset_tags` (
  `asset_id` int unsigned NOT NULL,
  `tag_id` int unsigned NOT NULL,
  PRIMARY KEY (`asset_id`,`tag_id`),
  KEY `fk_asset_tags_tag` (`tag_id`),
  CONSTRAINT `fk_asset_tags_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_asset_tags_tag` FOREIGN KEY (`tag_id`) REFERENCES `tags` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `asset_vuln_snapshot`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `asset_vuln_snapshot` (
  `snapshot_date` date NOT NULL,
  `asset_id` int unsigned NOT NULL,
  `open_count` int unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`snapshot_date`,`asset_id`),
  KEY `idx_snapshot_asset_date` (`asset_id`,`snapshot_date`),
  CONSTRAINT `fk_snapshot_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `assets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `assets` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `qualys_host_id` bigint unsigned NOT NULL,
  `qualys_asset_id` bigint unsigned DEFAULT NULL,
  `hostname` varchar(255) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `dns_name` varchar(255) DEFAULT NULL,
  `os` varchar(255) DEFAULT NULL,
  `tracking_method` varchar(20) DEFAULT NULL,
  `last_scan_date` datetime DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT '1',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_assets_qualys_host_id` (`qualys_host_id`),
  KEY `idx_assets_ip` (`ip_address`)
) ENGINE=InnoDB AUTO_INCREMENT=74028 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `audit_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `audit_log` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `occurred_at` datetime NOT NULL,
  `user_id` int unsigned DEFAULT NULL,
  `username` varchar(255) DEFAULT NULL,
  `action` varchar(64) NOT NULL,
  `target_type` varchar(32) DEFAULT NULL,
  `target_id` varchar(64) DEFAULT NULL,
  `target_label` varchar(255) DEFAULT NULL,
  `details` json DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_audit_log_occurred` (`occurred_at`),
  KEY `idx_audit_log_user` (`user_id`,`occurred_at`),
  KEY `idx_audit_log_action` (`action`,`occurred_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `cisa_kev`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cisa_kev` (
  `cve` varchar(30) NOT NULL,
  `vendor_project` varchar(255) DEFAULT NULL,
  `product` varchar(255) DEFAULT NULL,
  `vulnerability_name` varchar(512) DEFAULT NULL,
  `date_added` date DEFAULT NULL,
  `due_date` date DEFAULT NULL,
  `known_ransomware` tinyint(1) NOT NULL DEFAULT '0',
  `notes` mediumtext,
  `synced_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`cve`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `custom_remediations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `custom_remediations` (
  `qid` int unsigned NOT NULL,
  `remediation` mediumtext NOT NULL,
  `content_format` enum('text','html') NOT NULL DEFAULT 'text',
  `updated_by` int unsigned DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`qid`),
  KEY `fk_custom_remediation_user` (`updated_by`),
  CONSTRAINT `fk_custom_remediation_qid` FOREIGN KEY (`qid`) REFERENCES `knowledge_base` (`qid`) ON DELETE CASCADE,
  CONSTRAINT `fk_custom_remediation_user` FOREIGN KEY (`updated_by`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `detection_resolutions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `detection_resolutions` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `asset_id` int unsigned NOT NULL,
  `qid` int unsigned NOT NULL,
  `effective_cvss_score` decimal(3,1) DEFAULT NULL,
  `resolved_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_res_asset_date` (`asset_id`,`resolved_at`),
  KEY `idx_res_date` (`resolved_at`),
  CONSTRAINT `fk_res_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1721 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `epss_scores`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `epss_scores` (
  `cve` varchar(30) NOT NULL,
  `epss` decimal(6,5) NOT NULL,
  `percentile` decimal(6,5) NOT NULL,
  `score_date` date DEFAULT NULL,
  `synced_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`cve`),
  KEY `idx_epss_epss` (`epss`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `hidden_issues`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `hidden_issues` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int unsigned NOT NULL,
  `qid` int unsigned NOT NULL,
  `asset_id` int unsigned DEFAULT NULL,
  `asset_scope` int unsigned GENERATED ALWAYS AS (coalesce(`asset_id`,0)) STORED,
  `tag_id` int unsigned DEFAULT NULL,
  `tag_scope` int unsigned GENERATED ALWAYS AS (coalesce(`tag_id`,0)) STORED,
  `hidden_by` int unsigned DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_hidden_issue` (`user_id`,`qid`,`asset_scope`,`tag_scope`),
  KEY `fk_hidden_user` (`hidden_by`),
  KEY `idx_hidden_qid` (`qid`),
  KEY `idx_hidden_asset` (`asset_id`),
  KEY `idx_hidden_tag` (`tag_id`),
  CONSTRAINT `fk_hidden_qid` FOREIGN KEY (`qid`) REFERENCES `knowledge_base` (`qid`) ON DELETE CASCADE,
  CONSTRAINT `fk_hidden_user` FOREIGN KEY (`hidden_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_hidden_user_id` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `host_detections`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `host_detections` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `asset_id` int unsigned NOT NULL,
  `qid` int unsigned NOT NULL,
  `status` enum('New','Active','Fixed','Re-Opened') NOT NULL DEFAULT 'Active',
  `detection_type` varchar(20) DEFAULT NULL,
  `port` int unsigned DEFAULT NULL,
  `port_dedup_key` int unsigned GENERATED ALWAYS AS (coalesce(`port`,4294967295)) STORED,
  `protocol` varchar(10) DEFAULT NULL,
  `is_ssl` tinyint(1) NOT NULL DEFAULT '0',
  `first_found` datetime DEFAULT NULL,
  `last_found` datetime DEFAULT NULL,
  `last_fixed` datetime DEFAULT NULL,
  `times_found` int unsigned NOT NULL DEFAULT '1',
  `effective_cvss_score` decimal(3,1) DEFAULT NULL,
  `effective_cvss_source` enum('CVSS3','CVSS2','QUALYS_SEVERITY_ESTIMATE') DEFAULT NULL,
  `is_ce_plus_fail` tinyint(1) NOT NULL DEFAULT '0',
  `results` text,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_host_detections_asset_qid_portdedup` (`asset_id`,`qid`,`port_dedup_key`),
  KEY `idx_detections_status` (`status`),
  KEY `idx_detections_ce_plus` (`is_ce_plus_fail`),
  KEY `idx_detections_qid` (`qid`),
  KEY `idx_detections_first_found` (`first_found`),
  KEY `idx_detections_last_fixed` (`last_fixed`),
  CONSTRAINT `fk_detections_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_detections_qid` FOREIGN KEY (`qid`) REFERENCES `knowledge_base` (`qid`)
) ENGINE=InnoDB AUTO_INCREMENT=907872 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `kb_cve`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `kb_cve` (
  `qid` int unsigned NOT NULL,
  `cve` varchar(30) NOT NULL,
  PRIMARY KEY (`qid`,`cve`),
  KEY `idx_kb_cve_cve` (`cve`),
  CONSTRAINT `fk_kb_cve_qid` FOREIGN KEY (`qid`) REFERENCES `knowledge_base` (`qid`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `kev_alert_seen`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `kev_alert_seen` (
  `user_id` int unsigned NOT NULL,
  `asset_id` int unsigned NOT NULL,
  `qid` int unsigned NOT NULL,
  `seen_at` datetime NOT NULL,
  PRIMARY KEY (`user_id`,`asset_id`,`qid`),
  KEY `idx_kev_alert_seen_asset_qid` (`asset_id`,`qid`),
  CONSTRAINT `fk_kev_alert_seen_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_kev_alert_seen_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `knowledge_base`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `knowledge_base` (
  `qid` int unsigned NOT NULL,
  `title` varchar(500) NOT NULL,
  `severity_level` tinyint unsigned NOT NULL,
  `category` varchar(100) DEFAULT NULL,
  `cvss_base` decimal(3,1) DEFAULT NULL,
  `cvss_vector` varchar(255) DEFAULT NULL,
  `cvss3_base` decimal(3,1) DEFAULT NULL,
  `cvss3_vector` varchar(255) DEFAULT NULL,
  `cve_ids` text,
  `vendor_reference` text,
  `patchable` tinyint(1) NOT NULL DEFAULT '0',
  `pci_flag` tinyint(1) NOT NULL DEFAULT '0',
  `diagnosis` mediumtext,
  `consequence` mediumtext,
  `solution` mediumtext,
  `published_datetime` datetime DEFAULT NULL,
  `patch_published_date` datetime DEFAULT NULL,
  `qualys_last_modified` datetime DEFAULT NULL,
  `cached_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`qid`),
  KEY `idx_kb_severity` (`severity_level`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `login_throttle`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `login_throttle` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(45) NOT NULL,
  `attempted_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_login_throttle_ip_time` (`ip_address`,`attempted_at`),
  KEY `idx_login_throttle_time` (`attempted_at`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `organisation_tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `organisation_tags` (
  `organisation_id` int unsigned NOT NULL,
  `tag_id` int unsigned NOT NULL,
  PRIMARY KEY (`organisation_id`,`tag_id`),
  KEY `fk_organisation_tags_tag` (`tag_id`),
  CONSTRAINT `fk_organisation_tags_org` FOREIGN KEY (`organisation_id`) REFERENCES `organisations` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_organisation_tags_tag` FOREIGN KEY (`tag_id`) REFERENCES `tags` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `organisations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `organisations` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(191) NOT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT '1',
  `max_users` int unsigned DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_organisations_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `password_reset_tokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `password_reset_tokens` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int unsigned NOT NULL,
  `selector` char(24) NOT NULL,
  `token_hash` char(64) NOT NULL,
  `purpose` enum('setup','reset') NOT NULL DEFAULT 'reset',
  `requested_ip` varchar(45) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `expires_at` datetime NOT NULL,
  `used_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_password_reset_tokens_selector` (`selector`),
  KEY `idx_password_reset_tokens_user` (`user_id`),
  KEY `idx_password_reset_tokens_expires` (`expires_at`),
  CONSTRAINT `fk_password_reset_tokens_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `qid_exploit`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `qid_exploit` (
  `qid` int unsigned NOT NULL,
  `is_kev` tinyint(1) NOT NULL DEFAULT '0',
  `kev_cve` varchar(30) DEFAULT NULL,
  `kev_date_added` date DEFAULT NULL,
  `kev_due_date` date DEFAULT NULL,
  `kev_ransomware` tinyint(1) NOT NULL DEFAULT '0',
  `max_epss` decimal(6,5) DEFAULT NULL,
  `max_epss_percentile` decimal(6,5) DEFAULT NULL,
  `cve_count` int unsigned NOT NULL DEFAULT '0',
  `computed_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`qid`),
  KEY `idx_qid_exploit_kev` (`is_kev`),
  KEY `idx_qid_exploit_epss` (`max_epss`),
  CONSTRAINT `fk_qid_exploit_qid` FOREIGN KEY (`qid`) REFERENCES `knowledge_base` (`qid`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `qualys_api_call_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `qualys_api_call_log` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `endpoint` varchar(255) NOT NULL,
  `api_version` varchar(10) DEFAULT NULL,
  `called_at` datetime NOT NULL,
  `http_status` smallint unsigned DEFAULT NULL,
  `duration_sec` decimal(8,2) DEFAULT NULL,
  `response_bytes` int unsigned DEFAULT NULL,
  `rate_limit_remaining` int unsigned DEFAULT NULL,
  `rate_limit_limit` int unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_endpoint_called_at` (`endpoint`,`called_at`),
  KEY `idx_called_at` (`called_at`),
  KEY `idx_api_version_called_at` (`api_version`,`called_at`)
) ENGINE=InnoDB AUTO_INCREMENT=31337 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `qualys_tag_rules`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `qualys_tag_rules` (
  `qualys_tag_id` varchar(191) NOT NULL,
  `tag_name` varchar(255) DEFAULT NULL,
  `rule_type` varchar(64) DEFAULT NULL,
  `src_asset_group_id` bigint unsigned DEFAULT NULL,
  `found` tinyint(1) NOT NULL,
  `is_ip_based` tinyint(1) NOT NULL DEFAULT '0',
  `checked_at` datetime NOT NULL,
  PRIMARY KEY (`qualys_tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `scan_request_queue`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scan_request_queue` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `asset_id` int unsigned DEFAULT NULL,
  `qualys_host_id` bigint unsigned NOT NULL,
  `qualys_asset_id` bigint unsigned DEFAULT NULL,
  `hostname` varchar(255) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `status` enum('pending','processing','sent','failed') NOT NULL DEFAULT 'pending',
  `requested_by` int unsigned DEFAULT NULL,
  `requested_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `processed_at` datetime DEFAULT NULL,
  `attempts` int unsigned NOT NULL DEFAULT '0',
  `last_error` text,
  `active_dedup` bigint unsigned GENERATED ALWAYS AS ((case when (`status` in (_utf8mb4'pending',_utf8mb4'processing')) then `qualys_host_id` else NULL end)) STORED,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_scan_request_active_host` (`active_dedup`),
  KEY `idx_scan_request_status` (`status`),
  KEY `idx_scan_request_asset` (`asset_id`,`requested_at`),
  KEY `fk_scan_request_user` (`requested_by`),
  CONSTRAINT `fk_scan_request_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_scan_request_user` FOREIGN KEY (`requested_by`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=310 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `sync_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sync_log` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `sync_type` enum('knowledge_base','host_detections','exploit_intel','notifications') NOT NULL,
  `started_at` datetime NOT NULL,
  `completed_at` datetime DEFAULT NULL,
  `status` enum('running','success','failed') NOT NULL DEFAULT 'running',
  `records_processed` int unsigned NOT NULL DEFAULT '0',
  `error_message` text,
  PRIMARY KEY (`id`),
  KEY `idx_sync_log_type_started` (`sync_type`,`started_at`)
) ENGINE=InnoDB AUTO_INCREMENT=7323 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `sync_state`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sync_state` (
  `sync_type` varchar(50) NOT NULL,
  `state_json` text,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`sync_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `tags` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `qualys_tag_id` varchar(191) DEFAULT NULL,
  `name` varchar(255) NOT NULL,
  `ce_assessment_date` date DEFAULT NULL,
  `agent_activation_id` char(36) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_tags_qualys_tag_id` (`qualys_tag_id`)
) ENGINE=InnoDB AUTO_INCREMENT=33 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `user_tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_tags` (
  `user_id` int unsigned NOT NULL,
  `tag_id` int unsigned NOT NULL,
  PRIMARY KEY (`user_id`,`tag_id`),
  KEY `fk_user_tags_tag` (`tag_id`),
  CONSTRAINT `fk_user_tags_tag` FOREIGN KEY (`tag_id`) REFERENCES `tags` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_user_tags_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `user_trusted_devices`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_trusted_devices` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int unsigned NOT NULL,
  `selector` char(24) NOT NULL,
  `token_hash` char(64) NOT NULL,
  `device_label` varchar(255) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_used_at` datetime DEFAULT NULL,
  `expires_at` datetime NOT NULL,
  `revoked_at` datetime DEFAULT NULL,
  `revoked_by` int unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_trusted_devices_selector` (`selector`),
  KEY `fk_trusted_devices_revoked_by` (`revoked_by`),
  KEY `idx_trusted_devices_user` (`user_id`),
  KEY `idx_trusted_devices_expires` (`expires_at`),
  CONSTRAINT `fk_trusted_devices_revoked_by` FOREIGN KEY (`revoked_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_trusted_devices_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=25 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `is_admin` tinyint(1) NOT NULL DEFAULT '0',
  `can_uninstall_agents` tinyint(1) NOT NULL DEFAULT '0',
  `is_active` tinyint(1) NOT NULL DEFAULT '1',
  `failed_login_attempts` int unsigned NOT NULL DEFAULT '0',
  `locked_until` datetime DEFAULT NULL,
  `last_login_at` datetime DEFAULT NULL,
  `session_epoch` int unsigned NOT NULL DEFAULT '0',
  `default_tag_id` int unsigned DEFAULT NULL,
  `notify_frequency` enum('off','daily','weekly') NOT NULL DEFAULT 'off',
  `notify_watermark_id` bigint unsigned DEFAULT NULL,
  `notify_last_sent_at` datetime DEFAULT NULL,
  `mfa_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `mfa_secret` varchar(255) DEFAULT NULL,
  `mfa_confirmed_at` datetime DEFAULT NULL,
  `mfa_failed_attempts` int unsigned NOT NULL DEFAULT '0',
  `mfa_locked_until` datetime DEFAULT NULL,
  `mfa_last_used_counter` bigint unsigned DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `kev_alerts` tinyint(1) NOT NULL DEFAULT '1',
  `kev_alert_baseline_at` datetime DEFAULT NULL,
  `organisation_id` int unsigned DEFAULT NULL,
  `is_org_admin` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_users_username` (`username`),
  UNIQUE KEY `uq_users_email` (`email`),
  KEY `fk_users_default_tag` (`default_tag_id`),
  KEY `fk_users_organisation` (`organisation_id`),
  CONSTRAINT `fk_users_default_tag` FOREIGN KEY (`default_tag_id`) REFERENCES `tags` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_users_organisation` FOREIGN KEY (`organisation_id`) REFERENCES `organisations` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=16 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

