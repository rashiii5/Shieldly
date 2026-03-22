import sqlite3

conn = sqlite3.connect("shieldly.db")
cursor = conn.cursor()

cursor.execute("DELETE FROM questions WHERE id > 20")

conn.commit()
conn.close()
