/**
 * Client-side latency landmarks for constraint-based geolocation.
 *
 * The browser times requests to cloud endpoints at known coordinates. Light
 * in fibre covers about 200 km per millisecond, so a round trip of t ms
 * bounds the distance to t × 100 km (Octant / CBG). A VPN lengthens every
 * path by the client→exit leg, which shows up as latency that the claimed
 * IP location cannot explain (Weinberg et al., IMC 2018; SNITCH).
 *
 * Endpoints are AWS DynamoDB regional health checks ("/ping"), requested
 * with mode "no-cors": the response is opaque, but its arrival time is all
 * that is measured. No identifiers are sent.
 */

export interface Landmark {
  id: string;
  city: string;
  latitude: number;
  longitude: number;
  url: string;
}

export interface LandmarkMeasurement {
  id: string;
  city: string;
  latitude: number;
  longitude: number;
  /** Fastest of the timed samples (warm connection), in ms. */
  minMs: number | null;
  samples: number;
}

export interface LandmarkProbe {
  status: "collected" | "disabled" | "failed";
  measurements: LandmarkMeasurement[];
  durationMs: number;
}

const aws = (region: string, city: string, latitude: number, longitude: number): Landmark => ({
  id: region, city, latitude, longitude, url: `https://dynamodb.${region}.amazonaws.com/ping`,
});

export const LANDMARKS: Landmark[] = [
  aws("ap-south-1", "Mumbai", 19.08, 72.88),
  aws("ap-south-2", "Hyderabad", 17.39, 78.49),
  aws("ap-southeast-1", "Singapore", 1.35, 103.82),
  aws("ap-northeast-1", "Tokyo", 35.68, 139.69),
  aws("ap-southeast-2", "Sydney", -33.87, 151.21),
  aws("me-central-1", "UAE", 25.2, 55.27),
  aws("eu-central-1", "Frankfurt", 50.11, 8.68),
  aws("eu-west-2", "London", 51.51, -0.13),
  aws("us-east-1", "N. Virginia", 38.95, -77.45),
  aws("us-west-1", "N. California", 37.35, -121.96),
  aws("sa-east-1", "São Paulo", -23.55, -46.63),
  aws("af-south-1", "Cape Town", -33.92, 18.42),
];

async function timeRequest(url: string, timeoutMs: number): Promise<number | null> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  const started = performance.now();
  try {
    await fetch(`${url}?t=${Math.random().toString(36).slice(2)}`, { mode: "no-cors", cache: "no-store", credentials: "omit", signal: controller.signal });
    return performance.now() - started;
  } catch {
    return null;
  } finally {
    window.clearTimeout(timer);
  }
}

async function measure(landmark: Landmark): Promise<LandmarkMeasurement> {
  // The first request pays DNS, TCP and TLS setup; later ones reuse the
  // connection, so the fastest of them approximates one network round trip.
  await timeRequest(landmark.url, 4_000);
  const samples: number[] = [];
  for (let index = 0; index < 3; index += 1) {
    const elapsed = await timeRequest(landmark.url, 3_000);
    if (elapsed !== null) samples.push(elapsed);
  }
  return {
    id: landmark.id,
    city: landmark.city,
    latitude: landmark.latitude,
    longitude: landmark.longitude,
    minMs: samples.length ? Number(Math.min(...samples).toFixed(1)) : null,
    samples: samples.length,
  };
}

export async function collectLandmarkLatency(enabled: boolean): Promise<LandmarkProbe> {
  if (!enabled || typeof fetch !== "function") return { status: "disabled", measurements: [], durationMs: 0 };
  const started = performance.now();
  try {
    const measurements = await Promise.all(LANDMARKS.map(measure));
    const usable = measurements.filter((item) => item.minMs !== null).length;
    return { status: usable >= 3 ? "collected" : "failed", measurements, durationMs: Math.round(performance.now() - started) };
  } catch {
    return { status: "failed", measurements: [], durationMs: Math.round(performance.now() - started) };
  }
}
