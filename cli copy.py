import json
import os
from typing import Optional, Dict, Any

import typer

from .capture import capture_to_jsonl
from .io import read_jsonl, write_jsonl, to_alert
from .ml import (
    load_lstm_model,
    LSTMDetector,
    load_feature_config,
    extract_features_from_event,
    group_events,
    load_feature_list_pkl,
    load_external_scaler_pkl,
    resolve_model_artifacts,
)
from .sigma_engine import SigmaMatcher
from .realtime import realtime_monitor
from .cicflow_extract import extract_flows_from_pcap, capture_and_extract_flows
from .cicflow_realtime import capture_and_detect_realtime
from .packet_dropper import PacketDropper
from .logging_utils import init_logging, action as log_action, error as log_error, event as log_event, formatted as log_formatted, ml as log_ml


app = typer.Typer(help="CLI IDS: Sigma + LSTM-based anomaly detection")


def _common_logging_options(
    action_log: Optional[str],
    result_log: Optional[str],
    error_log: Optional[str],
    capture_event_log: Optional[str],
    ml_log: Optional[str],
    formatted_log: Optional[str],
) -> None:
    init_logging(
        action_log=action_log,
        result_log=result_log,
        error_log=error_log,
        event_log=capture_event_log,
        ml_log=ml_log,
        formatted_log=formatted_log,
    )


@app.callback()
def main(
    action_log: Optional[str] = typer.Option(
        None, help="Path to actions log file (default: logs/actions.log)"
    ),
    result_log: Optional[str] = typer.Option(
        None, help="Path to results log file (default: logs/results.log)"
    ),
    error_log: Optional[str] = typer.Option(
        None, help="Path to errors log file (default: logs/errors.log)"
    ),
    capture_event_log: Optional[str] = typer.Option(
        None, help="Path to capture events JSONL log (default: logs/captured_events.jsonl)"
    ),
    ml_log: Optional[str] = typer.Option(
        None, help="Path to ML evaluation log (default: logs/ml_log.log)"
    ),
    formatted_log: Optional[str] = typer.Option(
        None, help="Path to per-packet feature log (default: logs/formatpacket.jsonl)"
    ),
) -> None:
    """
    Global options for log file locations. All subcommands will share these paths.
    """
    _common_logging_options(
        action_log=action_log,
        result_log=result_log,
        error_log=error_log,
        capture_event_log=capture_event_log,
        ml_log=ml_log,
        formatted_log=formatted_log,
    )


@app.command()
def capture(
    output: str = typer.Option(..., "--output", "-o", help="Output JSONL path for captured events"),
    iface: Optional[str] = typer.Option(
        None, "--iface", help="Interface name to sniff on (leave empty for all)"
    ),
    duration: int = typer.Option(10, "--duration", "-d", help="Capture duration in seconds"),
    bpf: Optional[str] = typer.Option(
        None, "--bpf", help='Optional BPF filter, e.g. "tcp or udp"'
    ),
    bin_seconds: int = typer.Option(
        1, "--bin-seconds", help="Bin width in seconds for per-session aggregation"
    ),
) -> None:
    """
    Capture live traffic and write per-session, per-bin features to JSONL.
    """
    log_action(f"cli.capture start output={output} iface={iface} duration={duration}")
    try:
        count = capture_to_jsonl(
            output_path=output,
            iface=iface,
            duration=duration,
            bpf_filter=bpf,
            bin_seconds=bin_seconds,
        )
        log_action(f"cli.capture done count={count}")
    except Exception as e:
        log_error("cli.capture error", exc=e)
        raise typer.Exit(code=1)


@app.command()
def sigma(
    rules: str = typer.Option(..., "--rules", help="Path to Sigma rule file or directory"),
    input: str = typer.Option(..., "--input", "-i", help="Input JSONL events file"),
    output: str = typer.Option(..., "--output", "-o", help="Output JSONL alerts file"),
) -> None:
    """
    Run Sigma detection on JSONL events.
    """
    log_action(f"cli.sigma start rules={rules} input={input} output={output}")
    matcher = SigmaMatcher()
    matcher.load_path(rules)

    def _alerts():
        for ev in read_jsonl(input):
            hits = matcher.match_event(ev)
            if not hits:
                continue
            yield to_alert(ev, "sigma", {"sigma": hits})

    try:
        write_jsonl(output, _alerts())
        log_action("cli.sigma done")
    except Exception as e:
        log_error("cli.sigma error", exc=e)
        raise typer.Exit(code=1)


def _build_detector_from_artifacts(
    model_path: Optional[str],
    model_dir: Optional[str],
    features_config: Optional[str],
    feature_pkl: Optional[str],
    scaler_pkl: Optional[str],
    threshold: Optional[float],
) -> LSTMDetector:
    """
    Helper to build LSTMDetector, using feature.pkl / scaler.pkl when available.
    """
    resolved_model, resolved_feature_pkl, resolved_scaler_pkl = resolve_model_artifacts(
        model_path=model_path,
        model_dir=model_dir,
        feature_pkl=feature_pkl,
        scaler_pkl=scaler_pkl,
    )
    model = load_lstm_model(resolved_model)

    # Resolve feature names
    feature_names = []
    seq_len = 10
    th = threshold if threshold is not None else 0.5
    scaler_cfg = {}
    external_scaler = None

    if resolved_feature_pkl and os.path.exists(resolved_feature_pkl):
        feature_names = load_feature_list_pkl(resolved_feature_pkl)
    elif features_config:
        cfg = load_feature_config(features_config)
        feature_names = list(cfg.get("feature_names") or [])
        seq_len = int(cfg.get("sequence_length", seq_len))
        th = float(cfg.get("threshold", th))
        scaler_cfg = cfg.get("scaler") or {}
    else:
        raise typer.BadParameter(
            "No feature list provided. Use --feature-pkl, --model-dir with feature.pkl, "
            "or --features-config with feature_names."
        )

    if features_config and not resolved_feature_pkl:
        cfg = load_feature_config(features_config)
        seq_len = int(cfg.get("sequence_length", seq_len))
        th = float(cfg.get("threshold", th))
        scaler_cfg = cfg.get("scaler") or {}

    if resolved_scaler_pkl and os.path.exists(resolved_scaler_pkl):
        external_scaler = load_external_scaler_pkl(resolved_scaler_pkl)

    detector = LSTMDetector(
        model=model,
        feature_names=feature_names,
        sequence_length=seq_len,
        threshold=th,
        scaler_cfg=scaler_cfg,
        external_scaler=external_scaler,
    )
    return detector


@app.command()
def ml(
    model_path: Optional[str] = typer.Option(
        None, "--model-path", help="Path to LSTM .h5 model"
    ),
    model_dir: Optional[str] = typer.Option(
        None,
        "--model-dir",
        help="Directory containing model.h5, feature.pkl, scaler.pkl (optional)",
    ),
    features_config: Optional[str] = typer.Option(
        None,
        "--features-config",
        help="YAML config for features (sequence_length, threshold, scaler, feature_names)",
    ),
    feature_pkl: Optional[str] = typer.Option(
        None, "--feature-pkl", help="Pickle with list of feature names"
    ),
    scaler_pkl: Optional[str] = typer.Option(
        None, "--scaler-pkl", help="Pickle with external scaler (sklearn-style)"
    ),
    input: str = typer.Option(..., "--input", "-i", help="Input events file"),
    input_format: str = typer.Option(
        "jsonl", "--input-format", help="Input format: jsonl or csv"
    ),
    output: str = typer.Option(..., "--output", "-o", help="Output alerts JSONL"),
    group_field: Optional[str] = typer.Option(
        "session_id",
        "--group-field",
        help="Field name to group events into sequences (default: session_id)",
    ),
    time_field: Optional[str] = typer.Option(
        "timestamp",
        "--time-field",
        help="Field name for sorting within a group (default: timestamp)",
    ),
    threshold: Optional[float] = typer.Option(
        None, "--threshold", help="Override anomaly threshold"
    ),
) -> None:
    """
    Run LSTM-based anomaly detection on offline data (JSONL or CSV).
    """
    log_action(f"cli.ml start input={input} output={output}")
    detector = _build_detector_from_artifacts(
        model_path=model_path,
        model_dir=model_dir,
        features_config=features_config,
        feature_pkl=feature_pkl,
        scaler_pkl=scaler_pkl,
        threshold=threshold,
    )
    feature_names = detector.feature_names

    # Load events
    if input_format.lower() == "jsonl":
        events_iter = read_jsonl(input)
    elif input_format.lower() == "csv":
        import pandas as pd

        df = pd.read_csv(input)
        events_iter = (json.loads(row.to_json()) for _, row in df.iterrows())
    else:
        raise typer.BadParameter("input-format must be 'jsonl' or 'csv'")

    buckets = group_events(events_iter, group_field=group_field)

    def _alerts():
        for g_key, evs in buckets.items():
            # Sort within group by time field if present
            if time_field:
                evs.sort(key=lambda x: x.get(time_field))
            # Build feature rows
            rows = []
            for ev in evs:
                row = extract_features_from_event(ev, feature_names)
                if row is None:
                    continue
                rows.append(row)
            if not rows:
                continue
            flags = detector.predict_flags(rows)
            scores = detector.predict_scores(rows)
            for ev, flg, sc in zip(evs, flags, scores):
                if not flg:
                    continue
                detail = {
                    "ml": {
                        "hit": True,
                        "score": float(sc or 0.0),
                        "threshold": float(detector.threshold),
                    }
                }
                yield to_alert(ev, "ml", detail)

    try:
        write_jsonl(output, _alerts())
        log_action("cli.ml done")
    except Exception as e:
        log_error("cli.ml error", exc=e)
        raise typer.Exit(code=1)


@app.command()
def combined(
    rules: str = typer.Option(..., "--rules", help="Sigma rules path"),
    model_path: Optional[str] = typer.Option(
        None, "--model-path", help="Path to LSTM .h5 model"
    ),
    model_dir: Optional[str] = typer.Option(
        None, "--model-dir", help="Directory with model.h5, feature.pkl, scaler.pkl"
    ),
    features_config: Optional[str] = typer.Option(
        None, "--features-config", help="YAML config for ML features"
    ),
    feature_pkl: Optional[str] = typer.Option(
        None, "--feature-pkl", help="Pickle with list of feature names"
    ),
    scaler_pkl: Optional[str] = typer.Option(
        None, "--scaler-pkl", help="Pickle with external scaler (sklearn-style)"
    ),
    input: str = typer.Option(..., "--input", "-i", help="Input JSONL events"),
    output: str = typer.Option(..., "--output", "-o", help="Output alerts JSONL"),
    group_field: Optional[str] = typer.Option(
        "session_id", "--group-field", help="Field to group ML sequences (default: session_id)"
    ),
    time_field: Optional[str] = typer.Option(
        "timestamp", "--time-field", help="Field name for sorting within group"
    ),
    threshold: Optional[float] = typer.Option(
        None, "--threshold", help="Override ML threshold"
    ),
) -> None:
    """
    Run Sigma first, then ML for non-Sigma events on offline JSONL.
    """
    log_action(f"cli.combined start rules={rules} input={input} output={output}")
    matcher = SigmaMatcher()
    matcher.load_path(rules)
    detector = _build_detector_from_artifacts(
        model_path=model_path,
        model_dir=model_dir,
        features_config=features_config,
        feature_pkl=feature_pkl,
        scaler_pkl=scaler_pkl,
        threshold=threshold,
    )
    feature_names = detector.feature_names

    events = list(read_jsonl(input))
    buckets = group_events(iter(events), group_field=group_field)

    def _alerts():
        # Sigma alerts
        for ev in events:
            hits = matcher.match_event(ev)
            if hits:
                yield to_alert(ev, "sigma", {"sigma": hits})

        # ML alerts on remaining events
        for g_key, evs in buckets.items():
            if time_field:
                evs.sort(key=lambda x: x.get(time_field))
            rows = []
            for ev in evs:
                row = extract_features_from_event(ev, feature_names)
                if row is None:
                    continue
                rows.append(row)
            if not rows:
                continue
            flags = detector.predict_flags(rows)
            scores = detector.predict_scores(rows)
            for ev, flg, sc in zip(evs, flags, scores):
                if not flg:
                    continue
                yield to_alert(
                    ev,
                    "ml",
                    {
                        "ml": {
                            "hit": True,
                            "score": float(sc or 0.0),
                            "threshold": float(detector.threshold),
                        }
                    },
                )

    try:
        write_jsonl(output, _alerts())
        log_action("cli.combined done")
    except Exception as e:
        log_error("cli.combined error", exc=e)
        raise typer.Exit(code=1)


@app.command()
def realtime(
    rules: str = typer.Option(..., "--rules", help="Sigma rules path"),
    model_path: Optional[str] = typer.Option(
        None, "--model-path", help="Path to LSTM .h5 model"
    ),
    model_dir: Optional[str] = typer.Option(
        None, "--model-dir", help="Directory with model.h5, feature.pkl, scaler.pkl"
    ),
    features_config: Optional[str] = typer.Option(
        None, "--features-config", help="YAML config for ML features"
    ),
    feature_pkl: Optional[str] = typer.Option(
        None, "--feature-pkl", help="Pickle with list of feature names"
    ),
    scaler_pkl: Optional[str] = typer.Option(
        None, "--scaler-pkl", help="Pickle with external scaler (sklearn-style)"
    ),
    iface: Optional[str] = typer.Option(
        None, "--iface", help="Interface name to sniff on (e.g., eth0, Wi-Fi)"
    ),
    bpf: Optional[str] = typer.Option(
        None, "--bpf", help='Optional BPF filter, e.g. "tcp or udp"'
    ),
    bin_seconds: int = typer.Option(
        1, "--bin-seconds", help="Bin width in seconds for per-session aggregation"
    ),
    duration: Optional[int] = typer.Option(
        None,
        "--duration",
        "-d",
        help="Optional run duration in seconds (omit to run until Ctrl+C)",
    ),
    alerts_output: str = typer.Option(
        "alerts_realtime.jsonl",
        "--alerts-output",
        "-o",
        help="Path to append realtime alerts JSONL",
    ),
    threshold: Optional[float] = typer.Option(
        None, "--threshold", help="Override ML threshold"
    ),
) -> None:
    """
    Realtime IDS: capture traffic, run Sigma first, then ML for severity & anomaly scoring.
    """
    log_action(
        f"cli.realtime start rules={rules} iface={iface} duration={duration} "
        f"alerts_output={alerts_output}"
    )
    matcher = SigmaMatcher()
    matcher.load_path(rules)
    detector = _build_detector_from_artifacts(
        model_path=model_path,
        model_dir=model_dir,
        features_config=features_config,
        feature_pkl=feature_pkl,
        scaler_pkl=scaler_pkl,
        threshold=threshold,
    )

    try:
        realtime_monitor(
            rules_matcher=matcher,
            detector=detector,
            feature_names=detector.feature_names,
            alerts_output=alerts_output,
            iface=iface,
            duration=duration,
            bpf_filter=bpf,
            bin_seconds=bin_seconds,
        )
        log_action("cli.realtime done")
    except Exception as e:
        log_error("cli.realtime error", exc=e)
        raise typer.Exit(code=1)


@app.command()
def flow_extract(
    pcap: Optional[str] = typer.Option(
        None, "--pcap", help="Path to pcap file (for offline extraction)"
    ),
    iface: Optional[str] = typer.Option(
        None, "--iface", help="Network interface name (for realtime capture)"
    ),
    duration: Optional[int] = typer.Option(
        None,
        "--duration",
        "-d",
        help="Capture duration in seconds (for realtime, omit to run until Ctrl+C)",
    ),
    bpf: Optional[str] = typer.Option(
        None, "--bpf", help='BPF filter, e.g. "tcp or udp"'
    ),
    flow_timeout: float = typer.Option(
        120.0, "--flow-timeout", help="Flow expiration timeout in seconds"
    ),
    output: str = typer.Option(
        "flows.jsonl",
        "--output",
        "-o",
        help="Output JSONL file path",
    ),
) -> None:
    """
    Extract CICFlowMeter-style flow features from pcap or realtime capture.
    Outputs JSONL file ready for Sigma rules and ML detection.
    """
    log_action(
        f"cli.flow_extract start pcap={pcap} iface={iface} duration={duration} output={output}"
    )
    
    try:
        if pcap:
            # Offline extraction from pcap
            flows = extract_flows_from_pcap(
                pcap_path=pcap,
                flow_timeout=flow_timeout,
                output_jsonl=output,
            )
            log_action(f"cli.flow_extract done extracted {len(flows)} flows from pcap")
        elif iface:
            # Realtime capture and extraction
            flows = capture_and_extract_flows(
                iface=iface,
                duration=duration,
                bpf_filter=bpf,
                flow_timeout=flow_timeout,
                output_jsonl=output,
            )
            log_action(f"cli.flow_extract done extracted {len(flows)} flows from realtime")
        else:
            raise typer.BadParameter("Must provide either --pcap or --iface")
    except Exception as e:
        log_error("cli.flow_extract error", exc=e)
        raise typer.Exit(code=1)


@app.command(name="flow-ids")
def flow_ids(
    pcap: Optional[str] = typer.Option(
        None, "--pcap", help="Path to pcap file (for offline extraction)"
    ),
    iface: Optional[str] = typer.Option(
        None, "--iface", help="Network interface name (for realtime capture)"
    ),
    duration: Optional[int] = typer.Option(
        None,
        "--duration",
        "-d",
        help="Capture duration in seconds (for realtime, omit to run until Ctrl+C)",
    ),
    bpf: Optional[str] = typer.Option(
        None, "--bpf", help='BPF filter, e.g. "tcp or udp"'
    ),
    flow_timeout: float = typer.Option(
        120.0, "--flow-timeout", help="Flow expiration timeout in seconds"
    ),
    rules: str = typer.Option(
        ..., "--rules", help="Path to Sigma rule file or directory"
    ),
    model_path: Optional[str] = typer.Option(
        None, "--model-path", help="Path to LSTM .h5 model"
    ),
    model_dir: Optional[str] = typer.Option(
        None,
        "--model-dir",
        help="Directory containing model.h5, feature.pkl, scaler.pkl (optional)",
    ),
    features_config: Optional[str] = typer.Option(
        None,
        "--features-config",
        help="YAML config for features (sequence_length, threshold, scaler, feature_names)",
    ),
    feature_pkl: Optional[str] = typer.Option(
        None, "--feature-pkl", help="Pickle with list of feature names"
    ),
    scaler_pkl: Optional[str] = typer.Option(
        None, "--scaler-pkl", help="Pickle with external scaler (sklearn-style)"
    ),
    threshold: Optional[float] = typer.Option(
        None, "--threshold", help="Override ML anomaly threshold"
    ),
    flows_output: str = typer.Option(
        "flows.jsonl",
        "--flows-output",
        help="Intermediate flows JSONL file path",
    ),
    alerts_output: str = typer.Option(
        "alerts_combined.jsonl",
        "--alerts-output",
        "-o",
        help="Combined alerts JSONL output (Sigma + ML)",
    ),
    sigma_output: Optional[str] = typer.Option(
        None,
        "--sigma-output",
        help="Optional: separate Sigma alerts JSONL file",
    ),
    ml_output: Optional[str] = typer.Option(
        None,
        "--ml-output",
        help="Optional: separate ML alerts JSONL file",
    ),
) -> None:
    """
    Complete IDS workflow: Extract flows → Sigma detection → ML detection → Combined alerts.
    
    This command combines flow extraction, Sigma rule matching, and ML anomaly detection
    into a single pipeline. Outputs can be combined or separated.
    """
    log_action(
        f"cli.flow_ids start pcap={pcap} iface={iface} duration={duration} "
        f"rules={rules} alerts_output={alerts_output}"
    )
    
    try:
        # Step 1: Extract flows
        if pcap:
            flows = extract_flows_from_pcap(
                pcap_path=pcap,
                flow_timeout=flow_timeout,
                output_jsonl=flows_output,
            )
            log_action(f"cli.flow_ids extracted {len(flows)} flows from pcap")
        elif iface:
            # Realtime mode: detect immediately as flows complete
            log_action("cli.flow_ids starting realtime flow extraction with immediate detection")
            
            # Initialize Sigma and ML detectors
            matcher = SigmaMatcher()
            matcher.load_path(rules)
            detector = _build_detector_from_artifacts(
                model_path=model_path,
                model_dir=model_dir,
                features_config=features_config,
                feature_pkl=feature_pkl,
                scaler_pkl=scaler_pkl,
                threshold=threshold,
            )
            feature_names = detector.feature_names
            
            # Initialize packet dropper for dropping malicious packets
            packet_dropper = PacketDropper(enable_firewall_block=False)
            
            # Open alert files for appending
            os.makedirs(os.path.dirname(alerts_output) or ".", exist_ok=True)
            sigma_output_path = sigma_output or (alerts_output + ".sigma.jsonl")
            ml_output_path = ml_output or (alerts_output + ".ml.jsonl")
            combined_alert_f = open(alerts_output, "a", encoding="utf-8")
            sigma_alert_f = open(sigma_output_path, "a", encoding="utf-8") if sigma_output else None
            ml_alert_f = open(ml_output_path, "a", encoding="utf-8") if ml_output else None
            
            def write_alert(alert: Dict[str, Any], kind: str) -> None:
                """Write alert to appropriate files."""
                line = json.dumps(alert, ensure_ascii=False)
                combined_alert_f.write(line + "\n")
                combined_alert_f.flush()
                if kind == "sigma" and sigma_alert_f:
                    sigma_alert_f.write(line + "\n")
                    sigma_alert_f.flush()
                elif kind == "ml" and ml_alert_f:
                    ml_alert_f.write(line + "\n")
                    ml_alert_f.flush()
            
            def _prepare_flow(ev: Dict[str, Any]) -> Dict[str, Any]:
                """Prepare flow data for detection."""
                # Ensure proto field exists
                if "proto" not in ev:
                    protocol = ev.get("protocol", 0)
                    if protocol == 6:
                        ev["proto"] = "TCP"
                    elif protocol == 17:
                        ev["proto"] = "UDP"
                    elif protocol == 1:
                        ev["proto"] = "ICMP"
                    else:
                        ev["proto"] = str(protocol)
                # Map field names
                if "bytes_out" not in ev and "totlen_fwd_pkts" in ev:
                    ev["bytes_out"] = ev["totlen_fwd_pkts"]
                if "bytes_in" not in ev and "totlen_bwd_pkts" in ev:
                    ev["bytes_in"] = ev["totlen_bwd_pkts"]
                # Create session_id if needed
                if "session_id" not in ev:
                    src_ip = ev.get("src_ip", "")
                    src_port = ev.get("src_port", 0)
                    dst_ip = ev.get("dst_ip", "")
                    dst_port = ev.get("dst_port", 0)
                    ev["session_id"] = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                return ev
            
            def on_flow_complete(flow_data: Dict[str, Any]) -> None:
                """Called immediately when a flow completes - run Sigma first, then ML for severity/independent detection."""
                try:
                    ev = _prepare_flow(flow_data)
                    
                    # Log captured event
                    try:
                        log_event(json.dumps(ev, ensure_ascii=False))
                    except Exception:
                        pass
                    
                    # Log formatted flow features (similar to formatted packet log)
                    # Map all features that match feature_names exactly
                    try:
                        formatted_features = {}
                        for feat_name in feature_names:
                            # Try exact match first
                            if feat_name in ev:
                                formatted_features[feat_name] = ev[feat_name]
                            else:
                                # Try case-insensitive or common aliases
                                found = False
                                for k, v in ev.items():
                                    if k.lower() == feat_name.lower():
                                        formatted_features[feat_name] = v
                                        found = True
                                        break
                                if not found:
                                    formatted_features[feat_name] = 0.0
                        
                        formatted_entry = {
                            "timestamp": ev.get("timestamp"),
                            "src_ip": ev.get("src_ip"),
                            "dst_ip": ev.get("dst_ip"),
                            "src_port": ev.get("src_port"),
                            "dst_port": ev.get("dst_port"),
                            "proto": ev.get("proto"),
                            "flow_duration": ev.get("flow_duration", 0),
                            "features": formatted_features
                        }
                        log_formatted(json.dumps(formatted_entry, ensure_ascii=False))
                    except Exception as e:
                        log_error(f"cli.flow_ids:error logging formatted features {e}")
                    
                    # 1) Sigma detection FIRST
                    sigma_hits = matcher.match_event(ev)
                    
                    # 2) ML detection for severity assessment (if Sigma matched) or independent detection (if not)
                    row = extract_features_from_event(ev, feature_names)
                    ml_score = 0.0
                    ml_flag = False
                    ml_debug_info = {}
                    
                    if row is not None:
                        L = getattr(detector, 'L', 10)
                        if L > 1:
                            rows = [row] * L
                        else:
                            rows = [row]
                        
                        try:
                            flags = detector.predict_flags(rows)
                            scores = detector.predict_scores(rows)
                            ml_flag = flags[-1] if flags else False
                            ml_score = float(scores[-1] or 0.0) if scores else 0.0
                            
                            # Debug: Check for extreme values that might indicate attack but model misses
                            flow_pkts_s = ev.get("flow_pkts_s", 0)
                            flow_byts_s = ev.get("flow_byts_s", 0)
                            flow_duration = ev.get("flow_duration", 0)
                            
                            # If flow duration is extremely short (< 1ms) with high rates, model may miss it
                            # This is a known limitation: LSTM needs temporal patterns, but microsecond flows
                            # don't provide enough temporal context
                            if flow_duration > 0 and flow_duration < 0.001:  # < 1ms
                                ml_debug_info["very_short_duration"] = True
                                ml_debug_info["duration_us"] = flow_duration * 1e6
                            
                            if flow_pkts_s > 100000:  # Extremely high packet rate
                                ml_debug_info["extreme_packet_rate"] = flow_pkts_s
                            
                            if flow_byts_s > 50000000:  # Extremely high byte rate (>50MB/s)
                                ml_debug_info["extreme_byte_rate"] = flow_byts_s
                            
                            # Log ML evaluation with debug info
                            try:
                                log_ml(json.dumps({
                                    "ts": ev.get("timestamp"),
                                    "session_id": ev.get("session_id", ""),
                                    "phase": "flow_eval",
                                    "score": ml_score,
                                    "flag": ml_flag,
                                    "threshold": float(detector.threshold),
                                    "sigma_matched": len(sigma_hits) > 0,
                                    "debug": ml_debug_info,
                                    "flow_pkts_s": flow_pkts_s,
                                    "flow_byts_s": flow_byts_s,
                                    "flow_duration": flow_duration,
                                }, ensure_ascii=False))
                            except Exception:
                                pass
                        except Exception as e:
                            log_error(f"cli.flow_ids:error in ML detection {e}")
                    
                    # Workflow: If Sigma matched, use ML + heuristics to assess severity
                    if sigma_hits:
                        # Get Sigma rule level
                        sigma_level = (sigma_hits[0].get("level", "medium") or "medium").lower() if sigma_hits else "medium"
                        
                        # Base severity from Sigma rule level
                        if sigma_level == "high":
                            base_severity = "High"
                        elif sigma_level == "critical":
                            base_severity = "Critical"
                        else:
                            base_severity = "Medium"
                        
                        # Heuristic indicators for high severity (independent of ML score)
                        heuristic_indicators = []
                        
                        # High packet/byte rate
                        flow_pkts_s = ev.get("flow_pkts_s", 0)
                        flow_byts_s = ev.get("flow_byts_s", 0)
                        if flow_pkts_s > 10000:  # Very high packet rate
                            heuristic_indicators.append("high_packet_rate")
                        if flow_byts_s > 10000000:  # Very high byte rate (>10MB/s)
                            heuristic_indicators.append("high_byte_rate")
                        
                        # Extreme asymmetry
                        totlen_fwd = ev.get("totlen_fwd_pkts", 0)
                        totlen_bwd = ev.get("totlen_bwd_pkts", 0)
                        if totlen_fwd > 0:
                            asymmetry_ratio = totlen_bwd / totlen_fwd if totlen_fwd > 0 else 0
                            if asymmetry_ratio < 0.1 or asymmetry_ratio > 10:
                                heuristic_indicators.append("extreme_asymmetry")
                        
                        # SYN flood indicators
                        syn_count = ev.get("syn_flag_cnt", 0)
                        if syn_count > 5 and flow_pkts_s > 1000:
                            heuristic_indicators.append("syn_flood_pattern")
                        
                        # Final severity assessment
                        severity = base_severity
                        action_val = "alert"
                        
                        # Elevate severity if ML confirms OR strong heuristics
                        # NOTE: ML may miss very short-duration floods (< 1ms) because:
                        # 1. LSTM needs temporal patterns across multiple time steps
                        # 2. Single flow with microsecond duration = no temporal context
                        # 3. Model was likely trained on longer flows with clear patterns
                        # Solution: Trust Sigma + heuristics for high-confidence detections
                        if ml_flag:
                            severity = "High"
                            action_val = "drop"
                        elif ml_score > detector.threshold * 0.5:  # Medium score threshold
                            severity = "High" if base_severity == "High" else "Medium"
                            action_val = "drop" if severity == "High" else "alert"
                        elif len(heuristic_indicators) >= 2:  # Multiple strong indicators
                            severity = "High"
                            action_val = "drop"
                        elif len(heuristic_indicators) >= 1 and base_severity == "High":
                            severity = "High"
                            action_val = "drop"
                        elif base_severity == "High":
                            # Sigma rule says high, trust it even if ML score is low
                            # This is especially important for very short-duration floods where
                            # LSTM cannot detect temporal patterns (flow duration < 1ms)
                            severity = "High"
                            action_val = "drop"
                        
                        alert = dict(ev)
                        alert["_alert_kind"] = "sigma+ml"
                        alert["_alert_details"] = {
                            "sigma": sigma_hits,
                            "ml": {
                                "hit": ml_flag,
                                "score": ml_score,
                                "threshold": float(detector.threshold),
                                "why_low_score": "Flow duration too short for LSTM temporal patterns" if ml_debug_info.get("very_short_duration") else None,
                            },
                            "heuristics": heuristic_indicators,
                            "sigma_level": sigma_level,
                            "ml_debug": ml_debug_info if ml_debug_info else None,
                        }
                        alert["event_category"] = "network"
                        alert["event_type"] = "ids"
                        alert["severity"] = severity
                        alert["action"] = action_val
                        alert["rule"] = sigma_hits[0].get("title") if sigma_hits else None
                        write_alert(alert, "sigma")
                        log_action(
                            f"cli.flow_ids:sigma+ml_alert rule={alert.get('rule')} severity={severity} "
                            f"score={ml_score:.4f} heuristics={len(heuristic_indicators)} "
                            f"src={ev.get('src_ip')} dst={ev.get('dst_ip')}"
                        )
                        
                        # Drop malicious flow if action is "drop"
                        if action_val == "drop":
                            try:
                                src_ip = ev.get("src_ip", "")
                                src_port = ev.get("src_port", 0)
                                dst_ip = ev.get("dst_ip", "")
                                dst_port = ev.get("dst_port", 0)
                                protocol = ev.get("proto", "TCP")
                                packet_dropper.add_malicious_flow(
                                    src_ip=src_ip,
                                    src_port=src_port,
                                    dst_ip=dst_ip,
                                    dst_port=dst_port,
                                    alert_info=alert,
                                    protocol=protocol,
                                )
                            except Exception as e:
                                log_error(f"cli.flow_ids:error adding malicious flow to dropper {e}")
                    
                    # If Sigma didn't match, but ML detected anomaly
                    elif ml_flag:
                        alert = dict(ev)
                        alert["_alert_kind"] = "ml"
                        alert["_alert_details"] = {
                            "ml": {
                                "hit": True,
                                "score": ml_score,
                                "threshold": float(detector.threshold),
                            }
                        }
                        alert["event_category"] = "network"
                        alert["event_type"] = "ids"
                        alert["severity"] = "High"
                        alert["action"] = "drop"
                        write_alert(alert, "ml")
                        log_action(f"cli.flow_ids:ml_alert score={ml_score:.4f} src={ev.get('src_ip')} dst={ev.get('dst_ip')}")
                        
                        # Drop malicious flow
                        try:
                            src_ip = ev.get("src_ip", "")
                            src_port = ev.get("src_port", 0)
                            dst_ip = ev.get("dst_ip", "")
                            dst_port = ev.get("dst_port", 0)
                            protocol = ev.get("proto", "TCP")
                            packet_dropper.add_malicious_flow(
                                src_ip=src_ip,
                                src_port=src_port,
                                dst_ip=dst_ip,
                                dst_port=dst_port,
                                alert_info=alert,
                                protocol=protocol,
                            )
                        except Exception as e:
                            log_error(f"cli.flow_ids:error adding malicious flow to dropper {e}")
                
                except Exception as e:
                    log_error(f"cli.flow_ids:error processing flow {e}")
            
            # Start realtime capture with immediate detection callback
            capture_and_detect_realtime(
                iface=iface,
                duration=duration,
                bpf_filter=bpf,
                flow_timeout=flow_timeout,
                flows_output=flows_output,
                on_flow_complete=on_flow_complete,
            )
            
            # Close alert files
            combined_alert_f.close()
            if sigma_alert_f:
                sigma_alert_f.close()
            if ml_alert_f:
                ml_alert_f.close()
            
            log_action("cli.flow_ids realtime detection completed")
            return  # Skip offline processing steps
        
        else:
            # Use existing flows.jsonl if no pcap/iface provided
            if not os.path.exists(flows_output):
                raise typer.BadParameter(
                    f"Must provide --pcap or --iface, or ensure {flows_output} exists"
                )
            log_action(f"cli.flow_ids using existing flows file: {flows_output}")
        
        # Step 2: Sigma detection
        log_action("cli.flow_ids running Sigma detection")
        matcher = SigmaMatcher()
        matcher.load_path(rules)
        
        sigma_alerts = []
        sigma_output_path = sigma_output or (alerts_output + ".sigma.jsonl")
        
        # Prepare flows for Sigma matching
        def _prepare_for_sigma(events):
            for ev in events:
                # Ensure proto field exists for Sigma rules
                if "proto" not in ev:
                    protocol = ev.get("protocol", 0)
                    if protocol == 6:
                        ev["proto"] = "TCP"
                    elif protocol == 17:
                        ev["proto"] = "UDP"
                    elif protocol == 1:
                        ev["proto"] = "ICMP"
                    else:
                        ev["proto"] = str(protocol)
                # Map CICIDS field names to common names for Sigma
                if "bytes_out" not in ev and "totlen_fwd_pkts" in ev:
                    ev["bytes_out"] = ev["totlen_fwd_pkts"]
                if "bytes_in" not in ev and "totlen_bwd_pkts" in ev:
                    ev["bytes_in"] = ev["totlen_bwd_pkts"]
                yield ev
        
        sigma_checked = 0
        for event in _prepare_for_sigma(read_jsonl(flows_output)):
            sigma_checked += 1
            hits = matcher.match_event(event)
            if hits:
                alert = dict(event)
                alert["_alert_kind"] = "sigma"
                alert["_alert_details"] = {"sigma": hits}
                alert["event_category"] = "network"
                alert["event_type"] = "ids"
                alert["severity"] = hits[0].get("level", "medium").title() if hits else "Medium"
                alert["action"] = "alert"
                alert["rule"] = hits[0].get("title") if hits else None
                sigma_alerts.append(alert)
        
        log_action(f"cli.flow_ids Sigma: checked {sigma_checked} flows, {len(sigma_alerts)} alerts")
        
        # Write Sigma alerts
        if sigma_alerts:
            write_jsonl(sigma_output_path, iter(sigma_alerts))
            log_action(f"cli.flow_ids Sigma: {len(sigma_alerts)} alerts -> {sigma_output_path}")
        
        # Step 3: ML detection
        log_action("cli.flow_ids running ML detection")
        detector = _build_detector_from_artifacts(
            model_path=model_path,
            model_dir=model_dir,
            features_config=features_config,
            feature_pkl=feature_pkl,
            scaler_pkl=scaler_pkl,
            threshold=threshold,
        )
        feature_names = detector.feature_names
        
        # For flows, each flow is independent - process each flow as a single sequence
        # Create a session_id if not present and ensure each flow has required fields
        def _prepare_flows(events):
            for ev in events:
                if "session_id" not in ev:
                    # Create session_id from flow endpoints
                    src_ip = ev.get("src_ip", "")
                    src_port = ev.get("src_port", 0)
                    dst_ip = ev.get("dst_ip", "")
                    dst_port = ev.get("dst_port", 0)
                    ev["session_id"] = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                # Ensure proto field exists for Sigma rules
                if "proto" not in ev:
                    protocol = ev.get("protocol", 0)
                    if protocol == 6:
                        ev["proto"] = "TCP"
                    elif protocol == 17:
                        ev["proto"] = "UDP"
                    elif protocol == 1:
                        ev["proto"] = "ICMP"
                    else:
                        ev["proto"] = str(protocol)
                yield ev
        
        ml_alerts = []
        ml_output_path = ml_output or (alerts_output + ".ml.jsonl")
        
        # Process each flow independently (each flow is one sequence for LSTM)
        flow_count = 0
        processed_count = 0
        
        for ev in _prepare_flows(read_jsonl(flows_output)):
            flow_count += 1
            # Each flow is a single event, so create a sequence of length 1
            # But LSTM needs sequence_length, so we pad or use a single row
            row = extract_features_from_event(ev, feature_names)
            if row is None:
                log_action(f"cli.flow_ids:flow {flow_count} skipped - no features extracted")
                continue
            
            # For single flow, create a sequence by repeating the row to match sequence_length
            # Or use the flow as-is if sequence_length is 1
            L = getattr(detector, 'L', 10)
            if L > 1:
                # Pad with zeros or repeat the row
                rows = [row] * L
            else:
                rows = [row]
            
            try:
                flags = detector.predict_flags(rows)
                scores = detector.predict_scores(rows)
                
                # Use the last prediction (most recent)
                last_flag = flags[-1] if flags else False
                last_score = scores[-1] if scores else 0.0
                
                if last_flag:
                    alert = dict(ev)
                    alert["_alert_kind"] = "ml"
                    alert["_alert_details"] = {
                        "ml": {
                            "hit": True,
                            "score": float(last_score or 0.0),
                            "threshold": float(detector.threshold),
                        }
                    }
                    alert["event_category"] = "network"
                    alert["event_type"] = "ids"
                    alert["severity"] = "High"
                    alert["action"] = "drop"
                    ml_alerts.append(alert)
                    processed_count += 1
            except Exception as e:
                log_error(f"cli.flow_ids:error processing flow {flow_count}: {e}")
                continue
        
        log_action(f"cli.flow_ids ML: processed {flow_count} flows, {processed_count} alerts")
        
        # Write ML alerts
        if ml_alerts:
            write_jsonl(ml_output_path, iter(ml_alerts))
            log_action(f"cli.flow_ids ML: {len(ml_alerts)} alerts -> {ml_output_path}")
        
        # Step 4: Combine alerts
        combined_alerts = sigma_alerts + ml_alerts
        if combined_alerts:
            write_jsonl(alerts_output, iter(combined_alerts))
            log_action(
                f"cli.flow_ids done: {len(sigma_alerts)} Sigma + {len(ml_alerts)} ML = "
                f"{len(combined_alerts)} total alerts -> {alerts_output}"
            )
        else:
            log_action("cli.flow_ids done: no alerts detected")
    
    except Exception as e:
        log_error("cli.flow_ids error", exc=e)
        raise typer.Exit(code=1)


def _entry_point() -> None:
    app()


if __name__ == "__main__":
    _entry_point()


