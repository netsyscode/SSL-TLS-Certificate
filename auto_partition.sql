

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8 */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

-- 动态创建分区
DELIMITER //
CREATE PROCEDURE dynamic_partition(p_schema VARCHAR(64), p_table VARCHAR(64), p_max_partitions INT)
BEGIN
    DECLARE v_partition_num INT DEFAULT 0;
    DECLARE v_sql VARCHAR(1024) DEFAULT '';
    SELECT COUNT(*) INTO v_partition_num FROM information_schema.PARTITIONS WHERE TABLE_SCHEMA=p_schema AND TABLE_NAME=p_table;
    IF (v_partition_num<p_max_partitions) THEN
        SET @sql = CONCAT('ALTER TABLE `',p_schema,'`.`',p_table,'` ADD PARTITION (PARTITION p',DATE_FORMAT(NOW(),'%Y%m'),' VALUES LESS THAN (',UNIX_TIMESTAMP(LAST_DAY(NOW())),'))');
        PREPARE stmt1 FROM @sql;
        EXECUTE stmt1;
        DEALLOCATE PREPARE stmt1;
    END IF;
END;
//
DELIMITER ;

DROP EVENT IF EXISTS event_dynamic_partition;
CREATE EVENT event_dynamic_partition ON SCHEDULE EVERY 1 MONTH STARTS '2024-03-01 00:00:00' DO CALL dynamic_partition('authbase', 'SCAN_DATA', 60);

