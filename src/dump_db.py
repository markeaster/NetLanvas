import sqlite3

DB_PATH = "/app/db/network.db"

def check_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Get the total number of unique records
    cursor.execute("SELECT COUNT(*) FROM discovered_interfaces")
    total_rows = cursor.fetchone()[0]

    # Pull the 15 most recently updated records
    cursor.execute('''
        SELECT id, mac_address, ip_address, last_seen 
        FROM discovered_interfaces 
        ORDER BY last_seen DESC LIMIT 15
    ''')
    rows = cursor.fetchall()

    print("-" * 75)
    print(f"{'ID':<5} | {'MAC ADDRESS':<17} | {'IP ADDRESS':<15} | {'LAST SEEN (UTC)':<20}")
    print("-" * 75)
    
    for r in rows:
        print(f"{r[0]:<5} | {r[1]:<17} | {r[2]:<15} | {r[3]:<20}")
        
    print("-" * 75)
    print(f"Total Unique Interfaces Tracked: {total_rows}")
    
    conn.close()

if __name__ == "__main__":
    check_db()

