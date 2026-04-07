"""Tests for PerformanceMetrics and ThresholdTracker."""
from Handling.metrics import PerformanceMetrics, ThresholdTracker


def test_record_packet_counts_and_reports():
    m = PerformanceMetrics(window_size=1000)
    for _ in range(5):
        m.record_packet()
    stats = m.get_stats()
    assert stats["packets_processed"] == 5
    assert set(stats) == {"packets_processed", "packets_per_second", "avg_detection_time_ms"}


def test_detection_times_average_only_nonzero_samples():
    m = PerformanceMetrics(window_size=1000)
    m.record_packet(0.010)   # 10 ms
    m.record_packet(0.020)   # 20 ms
    m.record_packet(0)       # ignored, not a detection
    stats = m.get_stats()
    assert stats["packets_processed"] == 3
    assert stats["avg_detection_time_ms"] == 15.0


def test_throughput_computed_at_window_boundary():
    m = PerformanceMetrics(window_size=10)
    for _ in range(10):
        m.record_packet()
    # crossing the window boundary computes a positive packets/sec figure
    assert m.get_stats()["packets_per_second"] > 0


def test_should_block_only_after_threshold_reached():
    t = ThresholdTracker(count=3, window=60)
    assert t.should_block("10.0.0.1") is False
    assert t.should_block("10.0.0.1") is False
    assert t.should_block("10.0.0.1") is True


def test_threshold_is_tracked_per_ip():
    t = ThresholdTracker(count=2, window=60)
    assert t.should_block("10.0.0.1") is False
    # a different IP has its own independent counter
    assert t.should_block("10.0.0.2") is False
    assert t.should_block("10.0.0.1") is True


def test_state_resets_after_block():
    t = ThresholdTracker(count=2, window=60)
    t.should_block("10.0.0.1")
    assert t.should_block("10.0.0.1") is True
    # after firing, the counter starts fresh rather than blocking every packet
    assert t.should_block("10.0.0.1") is False
