def get_db_connection():
    import pymysql.cursors
    connection = pymysql.connect(host='localhost',
      user='webapp',
      password='webapp',
      db='security',
      charset='utf8mb4',
      cursorclass=pymysql.cursors.DictCursor)
    return connection
