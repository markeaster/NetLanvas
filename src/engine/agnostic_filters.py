import sqlite3
import logging

log = logging.getLogger("Netlanvas.Hardening")

def apply_db_hardening(db_path):
    """
    Enforces device and network-agnostic parsing laws at the ingestion layer.
    Rejects illogical network phenomena (Proxy-ARP bleeds, mDNS inter-VLAN reflections).
    """
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()

        # Harden against Proxy-ARP WAN bleeding and internal Docker bridge loops
        c.execute('''
        CREATE TRIGGER IF NOT EXISTS enforce_rfc1918_l3 BEFORE INSERT ON l3_bindings
        FOR EACH ROW
        BEGIN
            SELECT CASE
                WHEN NEW.ip_address LIKE '172.17.%' THEN RAISE(IGNORE)
                WHEN CAST(SUBSTR(NEW.ip_address, 1, INSTR(NEW.ip_address, '.') - 1) AS INTEGER) NOT IN (10, 172, 192, 169) THEN RAISE(IGNORE)
            END;
        END;
        ''')

        # Harden core infrastructure against broadcast protocol identity theft
        c.execute('''
        CREATE TRIGGER IF NOT EXISTS protect_core_identity BEFORE UPDATE OF os_family, hostname ON logical_nodes
        FOR EACH ROW
        WHEN OLD.weld_confidence = 100 AND OLD.device_type IN ('Router', 'Switch', 'Docker Host', 'Server', 'Printer')
        BEGIN
            SELECT CASE
                WHEN NEW.os_family = 'mDNS Node' THEN RAISE(IGNORE)
            END;
        END;
        ''')

        conn.commit()
        conn.close()
        log.info("Netlanvas.DB: Agnostic data validation rules strictly enforced on ephemeral DB.")
    except Exception as e:
        log.error(f"Netlanvas.DB: Failed to apply agnostic hardening: {e}")
