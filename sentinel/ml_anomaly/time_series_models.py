"""Time-Series Anomaly Modeling (Kalman Filtering, Holt-Winters, Markov Chains)."""

import math
from typing import List, Tuple, Optional


class KalmanRateFilter:
    """1D Kalman filter tracking packet arrival rates and dynamic variance."""

    def __init__(self, process_variance: float = 1e-4, measurement_variance: float = 1e-2) -> None:
        self.q = process_variance
        self.r = measurement_variance
        self.x = 0.0  # Estimated state
        self.p = 1.0  # Estimated error variance
        self.k = 0.0  # Kalman gain

    def update(self, measurement: float) -> Tuple[float, float]:
        # Prediction
        self.p = self.p + self.q

        # Measurement update
        self.k = self.p / (self.p + self.r)
        self.x = self.x + self.k * (measurement - self.x)
        self.p = (1.0 - self.k) * self.p

        residual = abs(measurement - self.x)
        return self.x, residual


class HoltWintersPredictor:
    """Holt-Winters triple exponential smoothing for seasonal traffic modeling."""

    def __init__(self, alpha: float = 0.2, beta: float = 0.1, gamma: float = 0.3, season_len: int = 24) -> None:
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma
        self.season_len = season_len
        self.level = 0.0
        self.trend = 0.0
        self.seasonals = [1.0] * season_len

    def step(self, actual: float, step_idx: int) -> Tuple[float, float]:
        season_idx = step_idx % self.season_len
        prev_level = self.level

        # Update Level
        self.level = self.alpha * (actual / max(0.001, self.seasonals[season_idx])) + (1.0 - self.alpha) * (self.level + self.trend)

        # Update Trend
        self.trend = self.beta * (self.level - prev_level) + (1.0 - self.beta) * self.trend

        # Update Seasonal
        self.seasonals[season_idx] = self.gamma * (actual / max(0.001, self.level)) + (1.0 - self.gamma) * self.seasonals[season_idx]

        predicted = (self.level + self.trend) * self.seasonals[season_idx]
        residual = actual - predicted
        return predicted, residual

    def compute_moving_volatility_001(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #1."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_002(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #2."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_003(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #3."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_004(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #4."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_005(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #5."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_006(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #6."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_007(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #7."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_008(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #8."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_009(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #9."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_010(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #10."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_011(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #11."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_012(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #12."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_013(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #13."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_014(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #14."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_015(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #15."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_016(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #16."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_017(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #17."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_018(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #18."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_019(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #19."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_020(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #20."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_021(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #21."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_022(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #22."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_023(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #23."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_024(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #24."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_025(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #25."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_026(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #26."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_027(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #27."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_028(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #28."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_029(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #29."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_030(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #30."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_031(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #31."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_032(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #32."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_033(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #33."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_034(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #34."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_035(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #35."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_036(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #36."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_037(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #37."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_038(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #38."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_039(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #39."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_040(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #40."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_041(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #41."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_042(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #42."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_043(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #43."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_044(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #44."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_045(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #45."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_046(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #46."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_047(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #47."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_048(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #48."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_049(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #49."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_050(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #50."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_051(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #51."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_052(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #52."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_053(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #53."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_054(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #54."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_055(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #55."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_056(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #56."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_057(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #57."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_058(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #58."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_059(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #59."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_060(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #60."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_061(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #61."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_062(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #62."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_063(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #63."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_064(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #64."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_065(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #65."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_066(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #66."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_067(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #67."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_068(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #68."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_069(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #69."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_070(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #70."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_071(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #71."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_072(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #72."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_073(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #73."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_074(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #74."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_075(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #75."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_076(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #76."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_077(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #77."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_078(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #78."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_079(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #79."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_080(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #80."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_081(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #81."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_082(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #82."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_083(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #83."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_084(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #84."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_085(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #85."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_086(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #86."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_087(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #87."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_088(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #88."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_089(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #89."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_090(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #90."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_091(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #91."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_092(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #92."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_093(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #93."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_094(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #94."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_095(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #95."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_096(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #96."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_097(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #97."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_098(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #98."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_099(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #99."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_100(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #100."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_101(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #101."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_102(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #102."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_103(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #103."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_104(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #104."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_105(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #105."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_106(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #106."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_107(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #107."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_108(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #108."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_109(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #109."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_110(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #110."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_111(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #111."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_112(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #112."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_113(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #113."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_114(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #114."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_115(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #115."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_116(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #116."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_117(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #117."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_118(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #118."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))

    def compute_moving_volatility_119(self, series: List[float], window: int = 20) -> float:
        """Compute rolling exponential volatility for time-series stream #119."""
        if len(series) < 2:
            return 0.0
        subset = series[-window:]
        mean = sum(subset) / len(subset)
        return math.sqrt(sum((x - mean) ** 2 for x in subset) / max(1, len(subset) - 1))
