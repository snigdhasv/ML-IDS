#!/bin/bash

# 🧠 Check for tmux
if ! command -v tmux &> /dev/null; then
    echo "Error: tmux is not installed. Install it and try again."
    exit 1
fi

# 🧠 Check for KAFKA_HOME
if [ -z "$KAFKA_HOME" ]; then
    echo "Error: KAFKA_HOME is not set. Export KAFKA_HOME and try again."
    exit 1
fi

# 💥 Kill existing session
tmux has-session -t kafka_pipeline 2>/dev/null && tmux kill-session -t kafka_pipeline

# 🚀 Start a new tmux session
tmux new-session -d -s kafka_pipeline -n 'Zookeeper'

# 🌐 Window 1: Zookeeper
echo "Starting Zookeeper..."
tmux send-keys "source venv/bin/activate && $KAFKA_HOME/bin/zookeeper-server-start.sh $KAFKA_HOME/config/zookeeper.properties" C-m
sleep 2

# 🕒 Wait for Zookeeper to be ready
while ! nc -z localhost 2181; do
    sleep 1
done
echo "Zookeeper started!"

# ⚙️ Window 2: Kafka
echo "Starting Kafka..."
tmux new-window -t kafka_pipeline -n 'Kafka'
tmux send-keys "source venv/bin/activate && $KAFKA_HOME/bin/kafka-server-start.sh $KAFKA_HOME/config/server.properties" C-m
sleep 2

# 🕒 Wait for Kafka to be ready
while ! nc -z localhost 9092; do
    sleep 1
done
echo "Kafka started!"

# 📡 Window 3: Kafka Simulation
echo "Starting Kafka Simulation..."
tmux new-window -t kafka_pipeline -n 'Kafka_Sim'
tmux send-keys "source venv/bin/activate && python3 kafka_sim.py" C-m
sleep 1

# 🤖 Window 4: ML Integration
echo "Starting ML Integration..."
tmux new-window -t kafka_pipeline -n 'ML_Integration'
tmux send-keys "source venv/bin/activate && python3 ml_integration.py" C-m

# 🎉 Attach to tmux session
tmux attach-session -t kafka_pipeline

echo "All processes started!"

