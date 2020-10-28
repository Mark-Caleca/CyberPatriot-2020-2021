::list network services that are listening (this could indicate a virus)
netstat -aon | find /i "listening"