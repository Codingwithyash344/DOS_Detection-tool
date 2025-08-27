from scapy.all import *
import time

class DoSDetector:
    def __init__(self, threshold=100):
        self.threshold = threshold
        self.packet_count = 0
        self.start_time = time.time()

    def packet_handler(self, packet):
        if IP in packet:
            self.packet_count += 1
            current_time = time.time()
            elapsed_time = current_time - self.start_time
            
            # Check if the packet count exceeds the threshold
            if elapsed_time < 1:  # Check in the last second
                if self.packet_count > self.threshold:
                    print(f"[ALERT] Possible DoS attack detected! Packets: {self.packet_count}")
            else:
                # Reset the counter every second
                self.packet_count = 0
                self.start_time = current_time

    def start_sniffing(self):
        print("Starting packet sniffing...")
        sniff(prn=self.packet_handler, store=0)

if __name__ == "__main__":
    detector = DoSDetector(threshold=100)  # Set threshold as needed
    detector.start_sniffing()
