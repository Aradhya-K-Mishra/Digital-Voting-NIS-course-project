from getpass import getpass
import hashlib
import mysql.connector


def login():
	connection = mysql.connector.connect(
	    host='ss3010.rutgers-sci.domains',
            user='ssrutge4_user1',
            password="qwer1234qwer",
            database='ssrutge4_ECE424'
	)

	employee_id = input("Enter Employee ID: ")

	# check if user exists
	query = "SELECT * FROM Employees WHERE id=%s"
	cursor = connection.cursor()
	cursor.execute(query, (employee_id,))
	records = cursor.fetchone()

	while records == None:
		print("Employee ID is not in the system. Please retype it.")
		employee_id = input("Enter Employee ID: ")

	# ask for password and hash it
	password = getpass("Enter Password: ")
	hashed_pass = hashlib.sha256()
	hashed_pass.update(password.encode('utf-8'))
	hashed_pass.digest()

	# get corresponding hashed password from database
	stored_pass = records[3]

	# check if passwords match
	count = 0
	while hashed_pass.hexdigest() != stored_pass:
		print(f'Stored password: {stored_pass}')
		print(f'Hashed password: {hashed_pass.hexdigest()}')

		if count == 2:
			print("3 Incorrect Password Attempts. You are locked out of your account.")
			return
			
		print("Passwords do not match. Please retype your password.")
		password = getpass("Enter Password: ")
		hashed_pass = hashlib.sha256()
		hashed_pass.update(password.encode('utf-8'))
		hashed_pass.digest()

		count += 1


	# get first name
	first_name = records[1]

	print("Login Successful!")
	cursor.close()
	connection.close()
	return employee_id, first_name
