import mysql.connector

try:
    mydb = mysql.connector.connect(
        host='ss3010.rutgers-sci.domains',
        user='ssrutge4_user1',
        password='qwer1234qwer',
        database='ssrutge4_ECE424',
        connect_timeout=5
    )
    print("Connection successful")
    mydb.close()
except Exception as e:
    print("Connection failed:", e)
