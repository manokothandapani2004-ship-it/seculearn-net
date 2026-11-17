import numpy as np


class LogisticViolationScorer:
    """
    11-parameter logistic violation-scoring model (10 behavioral features + 1 bias)
    executed in volatile client RAM (Section 3.5, Equation 5).
    """
    def __init__(self, lr: float = 0.01):
        self.weights = np.full(10, 0.1, dtype=np.float64)
        self.bias = -1.5
        self.lr = lr
        self.sample_count = 0

    @staticmethod
    def sigmoid(x: float) -> float:
        x_clipped = float(np.clip(x, -30.0, 30.0))
        return 1.0 / (1.0 + np.exp(-x_clipped))

    def step(self, z_features: list, y_label: int) -> dict:
        z = np.array(z_features[:10], dtype=np.float64)
        logit = float(np.dot(self.weights, z) + self.bias)
        s_hat = self.sigmoid(logit)

        eps = 1e-7
        loss = -(y_label * np.log(s_hat + eps) + (1.0 - y_label) * np.log(1.0 - s_hat + eps))

        error = s_hat - float(y_label)
        self.weights -= self.lr * error * z
        self.bias -= self.lr * error
        self.sample_count += 1

        params = [round(float(w), 6) for w in self.weights] + [round(float(self.bias), 6)]
        return {
            "score": round(s_hat, 4),
            "loss": round(float(loss), 4),
            "parameters": params,
            "n_k": self.sample_count
        }

    def set_global_parameters(self, global_theta: list):
        if global_theta and len(global_theta) == 11:
            self.weights = np.array(global_theta[:10], dtype=np.float64)
            self.bias = float(global_theta[10])


class FedAvgAggregator:
    @staticmethod
    def aggregate(client_updates: list) -> list:
        """
        Weighted FedAvg over 11-parameter vectors:
        theta^{(t+1)} = sum_{k=1}^K (n_k / n) * theta_k^{(t+1)}
        """
        if not client_updates:
            return [0.1] * 10 + [-1.5]
        total_n = sum(max(1, u.get("n_k", 1)) for u in client_updates)
        agg = np.zeros(11, dtype=np.float64)
        for u in client_updates:
            nk = max(1, u.get("n_k", 1))
            agg += (nk / total_n) * np.array(u["parameters"][:11], dtype=np.float64)
        return [round(float(x), 6) for x in agg]