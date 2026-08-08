
INPUT: environment_id
1. Load and verify the active hospital configuration.
2. Resolve environment-specific input, output, log, lock, and index names.
3. Collect recent Wazuh alerts and acquire Zeek conn.log.
4. Normalise events, generate stable IDs, and reject mismatched environments.
5. Resolve assets; evaluate policy and sliding-window behaviour.
6. Calculate standalone host and network scores and classifications.
7. Correlate endpoint-matched events inside the configured time window.
8. Replace standalone network records with correlated versions where applicable.
9. Publish unique documents by event_id and record pipeline state.
OUTPUT: environment-isolated, explainable investigation records.