class Bus:
    def __init__(self):
        self.events = []
    def publish(self, msg):
        self.events.append(msg)
        return msg

BUS = Bus()
