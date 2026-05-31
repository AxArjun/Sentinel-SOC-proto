CREATE DATABASE IF NOT EXISTS `threat_intel`;
USE `threat_intel`;

-- roles table
CREATE TABLE IF NOT EXISTS `roles` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(50) NOT NULL UNIQUE,
  `description` VARCHAR(255) NULL,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- permissions table
CREATE TABLE IF NOT EXISTS `permissions` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(100) NOT NULL UNIQUE,
  `description` VARCHAR(255) NULL,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- role_permissions junction table
CREATE TABLE IF NOT EXISTS `role_permissions` (
  `role_id` INT NOT NULL,
  `permission_id` INT NOT NULL,
  PRIMARY KEY (`role_id`, `permission_id`),
  FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`) ON DELETE CASCADE,
  FOREIGN KEY (`permission_id`) REFERENCES `permissions` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- users table
CREATE TABLE IF NOT EXISTS `users` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `username` VARCHAR(50) NOT NULL UNIQUE,
  `email` VARCHAR(100) NOT NULL UNIQUE,
  `password_hash` VARCHAR(255) NOT NULL,
  `role_id` INT NOT NULL,
  `is_active` TINYINT(1) DEFAULT 1,
  `last_login` DATETIME NULL,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_username` (`username`),
  INDEX `idx_is_active` (`is_active`),
  FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- threat_feeds table
CREATE TABLE IF NOT EXISTS `threat_feeds` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(100) NOT NULL UNIQUE,
  `feed_url` VARCHAR(500) NOT NULL,
  `feed_type` VARCHAR(50) NOT NULL,
  `auth_credentials` TEXT NULL,
  `is_enabled` TINYINT(1) DEFAULT 1,
  `last_sync` DATETIME NULL,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_is_enabled` (`is_enabled`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- threats table
CREATE TABLE IF NOT EXISTS `threats` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(150) NOT NULL UNIQUE,
  `description` TEXT NULL,
  `threat_actor` VARCHAR(100) NULL,
  `malware_family` VARCHAR(100) NULL,
  `severity_score` INT NOT NULL DEFAULT 50,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_threat_actor` (`threat_actor`),
  INDEX `idx_severity_score` (`severity_score`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- vulnerabilities table
CREATE TABLE IF NOT EXISTS `vulnerabilities` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `cve_id` VARCHAR(30) NOT NULL UNIQUE,
  `description` TEXT NULL,
  `cvss_score` DECIMAL(3, 1) NOT NULL,
  `epss_score` DECIMAL(5, 4) DEFAULT 0.0000,
  `patch_status` VARCHAR(50) DEFAULT 'Unpatched',
  `published_date` DATE NULL,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_cve_id` (`cve_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- threat_vulnerabilities junction table
CREATE TABLE IF NOT EXISTS `threat_vulnerabilities` (
  `threat_id` INT NOT NULL,
  `vulnerability_id` INT NOT NULL,
  PRIMARY KEY (`threat_id`, `vulnerability_id`),
  FOREIGN KEY (`threat_id`) REFERENCES `threats` (`id`) ON DELETE CASCADE,
  FOREIGN KEY (`vulnerability_id`) REFERENCES `vulnerabilities` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ioc table
CREATE TABLE IF NOT EXISTS `ioc` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `value` VARCHAR(255) NOT NULL UNIQUE,
  `type` VARCHAR(50) NOT NULL,
  `confidence` INT NOT NULL DEFAULT 50,
  `severity` VARCHAR(20) NOT NULL DEFAULT 'Medium',
  `threat_feed_id` INT NULL,
  `threat_id` INT NULL,
  `is_false_positive` TINYINT(1) DEFAULT 0,
  `first_seen` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `last_seen` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_value` (`value`),
  INDEX `idx_is_false_positive` (`is_false_positive`),
  FOREIGN KEY (`threat_feed_id`) REFERENCES `threat_feeds` (`id`) ON DELETE SET NULL,
  FOREIGN KEY (`threat_id`) REFERENCES `threats` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- incidents table
CREATE TABLE IF NOT EXISTS `incidents` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `title` VARCHAR(150) NOT NULL,
  `description` TEXT NULL,
  `status` VARCHAR(30) NOT NULL DEFAULT 'New',
  `priority` VARCHAR(20) NOT NULL DEFAULT 'Medium',
  `assigned_to` INT NULL,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `closed_at` DATETIME NULL,
  INDEX `idx_status` (`status`),
  INDEX `idx_priority` (`priority`),
  FOREIGN KEY (`assigned_to`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- alerts table
CREATE TABLE IF NOT EXISTS `alerts` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `title` VARCHAR(150) NOT NULL,
  `source` VARCHAR(100) NOT NULL,
  `matched_value` VARCHAR(255) NOT NULL,
  `severity` VARCHAR(20) NOT NULL,
  `status` VARCHAR(30) NOT NULL DEFAULT 'Unassigned',
  `ioc_id` INT NULL,
  `incident_id` INT NULL,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_matched_value` (`matched_value`),
  INDEX `idx_severity` (`severity`),
  INDEX `idx_status` (`status`),
  FOREIGN KEY (`ioc_id`) REFERENCES `ioc` (`id`) ON DELETE SET NULL,
  FOREIGN KEY (`incident_id`) REFERENCES `incidents` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- reports table
CREATE TABLE IF NOT EXISTS `reports` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `title` VARCHAR(150) NOT NULL,
  `report_type` VARCHAR(50) NOT NULL,
  `file_path` VARCHAR(500) NOT NULL,
  `generated_by` INT NOT NULL,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`generated_by`) REFERENCES `users` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- audit_logs table
CREATE TABLE IF NOT EXISTS `audit_logs` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NULL,
  `action` VARCHAR(100) NOT NULL,
  `details` TEXT NULL,
  `ip_address` VARCHAR(45) NOT NULL,
  `user_agent` VARCHAR(255) NULL,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_action` (`action`),
  INDEX `idx_created_at` (`created_at`),
  FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- system_settings table
CREATE TABLE IF NOT EXISTS `system_settings` (
  `setting_key` VARCHAR(100) PRIMARY KEY,
  `setting_value` TEXT NOT NULL,
  `setting_group` VARCHAR(50) NOT NULL,
  `description` VARCHAR(255) NULL,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
