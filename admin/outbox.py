"""Local outbox. Prod uses Postgres + JetStream."""
class Outbox:
    def __init__(self):
        self.rows = []
    def enqueue(self, topic, payload):
        self.rows.append({"topic": topic, "payload": payload, "published": False})
        return len(self.rows)
