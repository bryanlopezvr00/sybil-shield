# Sybil Attack Detection

A Next.js web application for detecting Sybil attacks in social and onchain platforms, where attackers organize in groups (e.g., WhatsApp) to create multiple fake accounts and coordinate attacks on specific users to manipulate leaderboards or rankings.

## Overview

This app focuses on graph-based and behavioral signal analysis to identify Sybil clusters. It supports data from GitHub (followers/stars), Farcaster/Base (onchain transactions, follows/casts), Talent Protocol, and Binance/Web3 (wallet clusters, trade patterns). The app visualizes interaction graphs, detects coordinated timing, behavioral anomalies, and churn signals to flag potential Sybil farms.

## Use Cases

- Defending open-source maintainers from coordinated ranking manipulation
- Auditing airdrop eligibility and wallet farms
- Investigating social graph abuse on emerging platforms

## Features

- Data upload for logs (CSV or JSON format: timestamp, actor, target, action, platform)
- Profile scanning for behavioral anomalies (account age, bio patterns, follower/following ratios)
- Graph visualization of interactions using Cytoscape.js
- Detection of tight clusters (potential Sybil farms)
- Timing coordination analysis (mass actions in short windows)
- Churn signal detection (high follow/unfollow or star/unstar waves)
- Behavioral anomaly scoring
- Output of suspicious clusters, waves, and high-churn actors

## Threat Model

### In-Scope Attacks

- Coordinated star/follow/unfollow waves targeting specific users to manipulate rankings.
- "Coordinated identity clusters": Dense internal interactions (mutual follows/stars) with low external connections.
- Airdrop-style wallet farms: Funding trees, shared funding sources, or clustered transfers.
- Cross-platform reuse: Same handle or wallet patterns across platforms.

### Out-of-Scope

- IP-based fingerprinting (unless user provides server logs with IPs).
- Private group evidence (e.g., WhatsApp/Telegram chats)—only inferred via timing and graph patterns.
- "Single-account harassment" (not Sybil, as it doesn't involve multiple identities).

This scope prevents unrealistic expectations and focuses on detectable Sybil behaviors.

## System Boundaries

- The system does **not** automatically block, ban, or report accounts.
- All outputs are **decision-support signals** intended for human review.
- Final enforcement actions (reporting, moderation, bans) are explicitly out of scope.
- The system prioritizes **false-negative tolerance over false positives** by default.

## Research Background

### What is a Sybil Attack?

Sybil attacks involve creating multiple fake identities to manipulate systems. In leaderboards or social platforms, attackers organize in external groups (e.g., WhatsApp) to plan coordinated attacks on specific users, such as mass unfollows/unstars to push them down rankings.

### Detection Approach

Focus on graph-based + behavioral signals, inspired by open-source projects:

- **Graph Clustering**: High mutual interactions in tightly connected components.
- **Timing Coordination**: Actions within seconds/minutes.
- **Behavioral Anomalies**: Low unique activity, repeated patterns, new accounts farming rewards.
- **Profile Analysis**: Account age, bio similarity, follower/following ratios.

### Profile Link Scanning

To detect coordinated link farming or spam patterns:

- Extract URLs from bio text
- Flag suspicious domains (e.g., link shorteners, known spam sites)
- Count shared links across accounts
- Detect patterns like identical or similar URLs
- Weight anomalies in profileAnomalyScore

Functions:

- `extractLinks(bio: string): string[]` - Parse URLs from bio
- `isSuspiciousDomain(url: string): boolean` - Check against blacklist
- `sharedLinkCount(actors: string[], links: Map<string, string[]>): number` - Count overlapping links
- `linkDiversityScore(links: string[]): number` - Unique domains / total links
- `updateProfileAnomalyScore(actor: string, links: string[]): number` - Incorporate into scoring

This helps identify Sybil farms promoting the same content.
- **Churn Signals**: Sudden waves of follow/unfollow or star/unstar.
- **Regional/Geographic Clustering**: If IP/language data available.

### Why Graph-Based First?

Pure ML approaches struggle with explainability and adversarial adaptation.
Graph-based methods provide:

- Transparent evidence (clusters, edges, timing)
- Human-verifiable explanations
- Resistance to simple feature spoofing

ML is treated as an augmentation layer, not the primary decision-maker.

### Data Sources

- GitHub: Followers list, stargazers per repo (via API or exports).
- Farcaster/Base: Onchain txns (Base explorer), follows/casts (Farcaster hubs).
- Talent Protocol: Talent scores, endorsements, and builder interactions.
- Binance/Web3: Wallet clusters, trade patterns.
- Logs: Timestamps of actions, regional/IP hints.

### Algorithm Overview

1. Build interaction graph from positive actions (follow, star, txn).
2. Detect large clusters (>5 nodes).
3. Analyze timing in 5-min bins for coordinated waves.
4. Score churn per actor.
5. Flag suspicious entities.

### Action Semantics

Actions are categorized to reduce false positives:

- **Positive edges** (graph-building): follow, star, transfer, fork
- **Negative edges** (churn signals): unfollow, unstar
- **Neutral actions**: comment, issue, PR (contextual weighting only)

Only positive edges contribute to cluster topology.
Negative edges are used exclusively for churn and wave detection.

Expand with ML: Centrality measures, DBSCAN on features.

### Open-Source Inspirations

- [ArbitrumFoundation/sybil-detection](https://github.com/ArbitrumFoundation/sybil-detection): On-chain graph partitioning.
- [TrustaLabs/Airdrop-Sybil-Identification](https://github.com/TrustaLabs/Airdrop-Sybil-Identification): Python ML for sybil clusters.
- [forkoooor/Sybil-Defender](https://github.com/forkoooor/Sybil-Defender): EVM chain monitoring.
- Farcaster-specific: Graph ML papers and Optimism grants.

## CSV/JSON Schema

### Required Fields

- `timestamp` (ISO8601 string, e.g., `2023-01-01T10:00:00Z`)
- `platform` (string: `github`, `farcaster`, `base`, `binance`, or custom)
- `action` (string: `follow`, `unfollow`, `star`, `unstar`, `transfer`, `swap`, `comment`, `fork`, `pr`, `issue`, `endorse`, `score`)
- `actor` (string: user handle or wallet address)
- `target` (string: user/repo/wallet/contract)

### Optional Fields

- `amount` (number: for weighting edges, e.g., transfer amount or star value)
- `txHash` (string: blockchain transaction hash)
- `blockNumber` (number: for onchain ordering)
- `meta` (JSON string: extra data like `{"repo": "owner/repo", "chainId": 8453, "token": "ETH"}`)
- `actorCreatedAt` (ISO8601: account creation time for age analysis)
- `followerCount` (number: current follower count for ratio analysis)
- `followingCount` (number: current following count for ratio analysis)
- `bio` (string: user bio text for pattern analysis)
- `location` (string: user location for geographic clustering)
- `verified` (boolean: if account is verified)
- `links` (array of strings: URLs from bio or profile)
- `targetType` (string: `repo`, `user`, `wallet`, etc.)

### Example CSV Snippet

```csv
timestamp,platform,action,actor,target,amount,meta
2023-01-01T10:00:00Z,github,follow,user1,user2,,{"repo": "example/repo"}
2023-01-01T10:01:00Z,github,star,user2,example/repo,,
2023-01-01T10:02:00Z,base,transfer,0x123...,0x456...,1000,{"chainId": 8453, "token": "ETH"}
2023-01-01T10:03:00Z,talent,endorse,user3,user4,,{"score": 85}
2023-01-01T10:04:00Z,farcaster,follow,user5,user6,,
```

### Example JSON Array

```json
[
  {
    "timestamp": "2023-01-01T10:00:00Z",
    "platform": "github",
    "action": "follow",
    "actor": "user1",
    "target": "user2",
    "meta": "{\"repo\": \"example/repo\"}"
  },
  {
    "timestamp": "2023-01-01T10:01:00Z",
    "platform": "github",
    "action": "star",
    "actor": "user2",
    "target": "example/repo"
  },
  {
    "timestamp": "2023-01-01T10:02:00Z",
    "platform": "talent",
    "action": "endorse",
    "actor": "user3",
    "target": "user4",
    "meta": "{\"score\": 85}"
  }
]
```

Weighting edges (e.g., by amount) improves detection quality.

## Data Ingestion

### CSV / JSON Upload

Minimum required fields: timestamp, platform, action, actor, target

Parser rules:

- Normalize timestamps to UTC
- Lowercase platform + action
- Deduplicate identical rows
- Reject files > configurable limit

### GitHub Ingestion

What GitHub allows: Stars (who starred + when), Follows (current list), Events (received activity)

What GitHub does NOT allow: Unstar events, Unfollow events, Historical removal logs

Use snapshots + diffs to prove unfollow/unstar waves.

Snapshot scripts provided in `/scripts`.

## Detection Pipeline

Order matters for accuracy:

1. **Build interaction graph**: Nodes (actor, target), Edges (actor → target), Weight (count or amount)
2. **Cluster detection**: Connected components, Size ≥ 5 → candidate cluster. Later: Louvain/Leiden modularity
3. **Timing coordination**: Bin events into 5-minute windows, Count actions per (target, action), Compute z-score vs baseline, Flag zScore > 3 AND actors ≥ 5
4. **Churn signals**: Heuristics (many actions toward same target, follow → unfollow patterns, star → unstar via diffs)
5. **Behavioral anomalies**: Low unique targets, New accounts, High repetition

## Evidence Generation

Every flag must generate:

```json
{
  "actor": "user123",
  "sybilScore": 0.71,
  "signals": [
    "Part of 9-node cluster",
    "7 unfollows in 1h",
    "Actions within 120s window",
    "Account age < 3 days"
  ],
  "linkedActors": ["userA", "userB", "userC"]
}
```

No evidence → no claim.

## Frontend Flow

Upload file OR connect GitHub → Click "Analyze" → Show: Graph, Clusters, Waves, Actor scorecards → Export: CSV, JSON, ZIP evidence pack

## Storage Choices

Best MVP stack:

- **Blob Storage** (Vercel/Cloudflare): CSV uploads & reports
- **Postgres** (Neon/Supabase): Entities, runs, scores, audit trail
- **Redis** (Upstash): Queues, rate limits, caching
- **Edge Config** (Vercel): Thresholds ONLY (never data)

Do NOT use: Redis as primary DB, Edge Config for logs, Mongo for graph analysis

## What to Add Next (Ordered)

1. Synthetic attack generator
2. GitHub App integration
3. Onchain funding tree detection
4. Human review mode
5. Exportable platform report format

## What NOT to Claim

Never say: "We detected Sybil attackers", "These accounts are fake"

Always say: "Activity consistent with coordinated behavior", "Risk indicators exceeded thresholds"

This keeps the project legally safe, scientifically credible, and taken seriously by platforms.

## Detection Outputs

The app returns structured results for transparency and defensibility:

- **Cluster Results**: `clusterId`, `members` (list), `density` (internal edges / possible edges), `conductance` (external edges / internal edges), `externalEdges`.
- **Wave Results**: `windowStart`, `windowEnd`, `action`, `target`, `actors` (list), `zScore` (deviation from expected).
- **Actor Scorecard**: `sybilScore` (0-1), `churnScore`, `coordinationScore`, `noveltyScore`.
- **Evidence Pack**: "Why flagged" summary with top signals (e.g., "High churn: 8 unfollows in 1 hour; Part of cluster with 10 members").

### Confidence Levels

Each flagged entity is assigned a confidence tier:

- **Low**: Anomalous behavior detected, weak coordination evidence
- **Medium**: Multiple signals align (timing + churn or clustering)
- **High**: Dense clusters + strong temporal coordination

Confidence is derived from signal agreement, not score magnitude alone.

Outputs are risk flags, not accusations, to avoid doxxing.

## Scoring Model

Even heuristic-based, the model is explicit and configurable:

**SybilScore(actor) = 0.30 * coordinationScore + 0.20 * churnScore + 0.15 * clusterIsolationScore + 0.10 * newAccountScore + 0.10 * lowDiversityScore + 0.15 * profileAnomalyScore**

- **coordinationScore**: Fraction of actions in bursts (>10 in 5-min window).
- **churnScore**: Number of unfollow/unstar actions.
- **clusterIsolationScore**: 1 - (external connections / total connections).
- **newAccountScore**: 1 if account age < 7 days, else 0.
- **lowDiversityScore**: 1 - (unique targets / total actions).
- **profileAnomalyScore**: 1 if follower/following ratio < 0.1 or bio matches common spam patterns, or links to suspicious domains/shared links, else 0.

Thresholds (e.g., SybilScore > 0.6) are configurable per platform. Tune via environment variables.

## False Positive Mitigations

The system explicitly reduces false positives by:

- Ignoring clusters smaller than configurable thresholds
- Discounting long-lived accounts with diverse activity
- Down-weighting actions spread over long time windows
- Separating organic growth spikes from coordinated bursts
- Allowing per-platform threshold tuning

## Adversarial Considerations

Attackers may attempt to evade detection by:

- Spreading actions over longer windows
- Introducing noise via organic interactions
- Mixing real and fake accounts
- Reusing compromised aged accounts

Mitigations include adaptive windows, entropy measures, and cross-platform correlation.

## Graph Methods

Concrete algorithms for cluster and timing detection:

- **Cluster Discovery**: Connected components (for dense groups) or Louvain/Leiden modularity (for hierarchical clusters).
- **Group Tightness**: Triangle count or clustering coefficient (measures mutual connections).
- **Isolation**: Conductance or cut ratio (low external edges indicate farms).
- **Reciprocity**: Fraction of mutual follows/stars.
- **Temporal Bursts**: 5-min binning + z-score (deviation) or Poisson burst detection for waves.

Start with connected components + heuristics; expand to ML later.

## Evaluation & Benchmarks

To build trust and iterate:

- **Synthetic Generator**: Create fake Sybil clusters (e.g., 10 accounts mutually following, bursting on a target) + organic users.
- **Metrics**: Precision/recall on synthetic ground truth; false positive review rate (<5%).
- **Scenario Configs**: Save seeds for reproducibility (e.g., clusterSize=10, burstWindow=300s).

This enables fast iteration without real data risks.

## Privacy & Safety

- Data uploaded stays local (no server storage unless opted-in).
- No IP collection unless user provides logs.
- Outputs are "risk flags" for personal defense/reporting, not public accusations.
- Anonymized reporting to platforms (e.g., Base/Farcaster) via aggregated stats.

Protects users and the project.

## Integrations (Roadmap)

Planned concrete endpoints for real data:

- **GitHub**: REST API (stargazers, followers, events, user profiles for age/bio/follower counts). Rate limit handling. Optional GitHub App for private repos.
- **Base/Onchain**: RPC via Alchemy/QuickNode. Transfer graphs from ERC20 events. Funding-tree detection ("common funder" chains). Wallet profiles via ENS or onchain data.
- **Talent Protocol**: API for talent scores, endorsements, and builder networks. Sybil detection for decentralized talent verification.
- **Farcaster**: Hub API or Neynar. Follow/cast graphs. User profiles (bio, followers, created_at).

## Deployment & Storage

Suggested MVP architecture:

- **Blob Storage** (Vercel/Cloudflare): For CSV uploads and generated reports.
- **Postgres** (Neon/Supabase): Entities, runs, scores, audit trail.
- **Redis** (Upstash): Rate limits, job queues, caching.
- **Edge Config** (Vercel): Feature flags, thresholds (not data).

Deployable on Vercel for simplicity.

## Abuse Response Playbook

Since Sybil attacks are common:

- **Lock Repo Interactions**: Enable branch protection, require approvals.
- **Export Evidence**: CSV + JSON summary of flagged actors/clusters.
- **Report to Platform**: Anonymized patterns to GitHub/Base/Farcaster teams.
- **Evidence Pack Format**: Structured for platform reports.

## Screenshots / Demo

- Graph view: Interactive Cytoscape graph of interactions.
- Cluster report: List of suspicious clusters with members (see Sample Reports).
- Wave/timing chart: Bursts highlighted.
- Export evidence: Downloadable pack (JSON example above).

(Sample outputs provided above; add actual screenshots later.)

## Project Structure

- `/app`: Next.js routes (upload, results, API endpoints)
  - `page.tsx`: Landing / upload
  - `analyze/page.tsx`: Analysis results
  - `api/analyze/route.ts`: Main analysis endpoint
  - `api/github/route.ts`: GitHub fetcher
- `/lib`: Core logic
  - `ingest/`: Data ingestion (CSV, JSON, GitHub)
  - `graph/`: Graph building and clustering
  - `signals/`: Detection signals (timing, churn, etc.)
  - `scoring/`: Sybil score calculation
  - `evidence/`: Evidence generation
- `/components`: React components (Upload, GraphView, etc.)
- `/datasets`: Sample and synthetic data
- `/scripts`: Shell scripts for GitHub snapshots

## Getting Started

### Prerequisites

- Node.js 18+
- npm or yarn

### Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```

### Running the App

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to view the app.

### Building for Production

```bash
npm run build
npm start
```

## Usage

1. Upload a CSV or JSON file with the required fields: timestamp, actor, target, action, platform.
   - Actions: follow, star, unfollow, unstar, etc.
   - Platforms: github, farcaster, binance, etc.
2. Click "Start Analysis" to process the data.
3. View the interaction graph.
4. See detected suspicious clusters, coordinated waves, and high-churn actors.
5. Export evidence pack as JSON.

A sample CSV file `sample_logs.csv` is provided for testing.

## Sample Reports

The app generates structured JSON reports for clusters, waves, actor scorecards, and evidence packs. Below are examples based on the sample data.

### Example Cluster Results

```json
[
  {
    "clusterId": 1,
    "members": ["user1", "user2", "user3", "user4", "user5", "user6", "user7", "user8", "user9", "user10"],
    "density": 0.2,
    "conductance": 0.8,
    "externalEdges": 2
  }
]
```

### Example Wave Results

```json
[
  {
    "windowStart": "2023-01-01T10:19:00Z",
    "windowEnd": "2023-01-01T10:27:00Z",
    "action": "unfollow",
    "target": "user3",
    "actors": ["user1", "user2", "user4", "user5", "user6", "user7", "user8", "user9", "user10"],
    "zScore": 3.5
  }
]
```

### Example Actor Scorecard

```json
{
  "user1": {
    "sybilScore": 0.75,
    "churnScore": 0.8,
    "coordinationScore": 0.9,
    "noveltyScore": 0.1,
    "confidence": "High"
  },
  "user2": {
    "sybilScore": 0.72,
    "churnScore": 0.8,
    "coordinationScore": 0.9,
    "noveltyScore": 0.1,
    "confidence": "High"
  }
}
```

### Example Evidence Pack (JSON Export)

```json
{
  "summary": "High-confidence Sybil cluster detected with coordinated unfollow wave.",
  "clusters": [...],
  "waves": [...],
  "scorecards": {...},
  "exportedAt": "2023-01-01T12:00:00Z"
}
```

These reports can be exported as JSON for further analysis or reporting to platforms.

## Technologies Used

- Next.js 14
- React
- TypeScript
- Tailwind CSS
- Cytoscape.js for graph visualization
- PapaParse for CSV parsing

## Future Improvements

- Integrate Python backend for advanced analysis (networkx, pandas).
- Add ML models (LightGBM on subgraphs).
- Support real API integrations (GitHub, Base, Binance).
- Human review interface.
- Anonymized reporting to platforms.

## References

- [Sybil Attack - Wikipedia](https://en.wikipedia.org/wiki/Sybil_attack)
- Yu et al. (2008). SybilGuard: defending against sybil attacks via social networks.
- Cao et al. (2012). Aiding the detection of fake accounts in large scale social online services.
- Arbitrum Sybil Detection
- TrustaLabs Airdrop Sybil Identification

## License

MIT
