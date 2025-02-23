#!/bin/bash
echo "Applying capabilities to server..."
sudo /usr/sbin/setcap cap_net_bind_service=+ep build/server || echo "❌ setcap failed!"
echo "Done!"
