import mysql.connector
from datetime import datetime, timedelta, timezone

# 连接数据库
conn = mysql.connector.connect(
    host="your_host",
    user="your_user",
    password="your_password",
    database="your_database"
)

cursor = conn.cursor()

try:
    # 获取当前日期的前一个月的年月份字符串，例如202203
    last_month = (datetime.now(timezone.utc) - timedelta(days=30)).strftime('%Y%m')

    # 创建临时表
    create_temp_table_query = f"CREATE TABLE TmpDeviceData LIKE DeviceData;"
    cursor.execute(create_temp_table_query)

    # 锁住表
    lock_tables_query = "LOCK TABLES DeviceData WRITE, TmpDeviceData WRITE;"
    cursor.execute(lock_tables_query)

    # 交换分区到临时表
    swap_partition_query = f"ALTER TABLE DeviceData EXCHANGE PARTITION pmax WITH TABLE TmpDeviceData;"
    cursor.execute(swap_partition_query)

    # 拆分分区
    reorganize_partition_query = f"""
        ALTER TABLE DeviceData REORGANIZE PARTITION pmax INTO (
            PARTITION p{last_month} VALUES LESS THAN ({last_month}01),
            PARTITION pmax VALUES LESS THAN (MAXVALUE)
        );
    """
    cursor.execute(reorganize_partition_query)

    # 再次交换分区
    swap_back_query = f"ALTER TABLE DeviceData EXCHANGE PARTITION p{last_month} WITH TABLE TmpDeviceData WITHOUT VALIDATION;"
    cursor.execute(swap_back_query)

    # 解锁表
    unlock_tables_query = "UNLOCK TABLES;"
    cursor.execute(unlock_tables_query)

    # 提交事务
    conn.commit()

except Exception as e:
    # 发生异常时回滚事务
    conn.rollback()
    print(f"Error: {e}")

finally:
    # 关闭连接
    cursor.close()
    conn.close()

