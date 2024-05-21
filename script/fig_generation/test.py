

from datetime import datetime, timezone

# 假设 dt1 是 offset-aware，dt2 是 offset-naive
dt1 = datetime.now(timezone.utc)  # 创建一个带有 UTC 时区信息的当前时间对象
dt2 = datetime.now()  # 创建一个没有时区信息的当前时间对象

# 如果 dt2 是 offset-naive，将其转换为 offset-aware
if dt2.tzinfo is None:
    dt2 = dt2.replace(tzinfo=timezone.utc)

# 确保两个对象都是 offset-aware
# 然后进行操作
print(dt1)
print(dt2)
print(dt1.strftime("%Y%m%d%H%M%S"))
print(dt1)
