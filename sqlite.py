import sqlite3

# Connect to the database (create a new file if it doesn't exist)
conn = sqlite3.connect('instance/user.db')

# Create a cursor object to execute SQL statements
cursor = conn.cursor()

# Execute a query
cursor.execute("SELECT * FROM user")

# Fetch all rows from the result set
rows = cursor.fetchall()

# Iterate over the rows and print the data
for row in rows:
    print(row)

# Close the cursor and the connection
cursor.close()
conn.close()
