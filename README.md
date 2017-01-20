# aws_redalert
AWS CloudWatch Event based account monitoring for security relevant events.

# Deploy:
```
workon gitlamb
mkdir libs
pip install -t $( pwd )/libs -r requirements.txt
python <pathto>/gitlamb.py deploy sec_alerts.yaml
```

# Configure:
```
python <pathto>/gitlamb.py execute sec_alerts.yaml "{\"action\": \"configure\"}"
```

