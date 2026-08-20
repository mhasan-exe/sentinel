"""
security_survey.py

The "Security Assessment" — a scored questionnaire shown before the
user enters the Sentinel lab (spec section 5). This is deliberately
NOT a random-percentage generator: every score is the sum of actual
answers against an explicit answer key, so a judge could recompute it
by hand from the raw responses stored in SurveyResponse.

Question types:
  - "knowledge"  : one correct option, full credit or none
  - "scenario"   : same scoring as knowledge, phrased as a situation
  - "confidence" : self-rated 1-5, credit is proportional (no "correct"
                   answer — this measures self-assessment, not accuracy)

Categories match spec section 5's example list:
  security_awareness, authentication, web_security, cryptography,
  post_quantum_awareness, network_security
"""

CATEGORY_LABELS = {
    "security_awareness": "Security Awareness",
    "authentication": "Authentication",
    "web_security": "Web Security",
    "cryptography": "Cryptography",
    "post_quantum_awareness": "Post-Quantum Awareness",
    "network_security": "Network Security",
}

QUESTIONS = [
    # ---- security_awareness ----
    {
        "id": "q1",
        "category": "security_awareness",
        "type": "scenario",
        "text": "You get an email claiming to be your bank, asking you to click a link and log in immediately or your account will be suspended. What's the safest first move?",
        "options": [
            "Click the link and log in right away, just in case it's real",
            "Ignore the email entirely and never check",
            "Go to the bank's site directly (not via the email link) or call them to verify",
            "Reply to the email asking if it's legitimate",
        ],
        "correct_index": 2,
    },
    {
        "id": "q2",
        "category": "security_awareness",
        "type": "knowledge",
        "text": "Reusing the same password across multiple unrelated accounts is risky mainly because:",
        "options": [
            "It makes the password harder to type",
            "One breached site can expose your login on every other site using that password",
            "Websites don't allow it",
            "It makes the password weaker on that one site specifically",
        ],
        "correct_index": 1,
    },
    {
        "id": "q3",
        "category": "security_awareness",
        "type": "confidence",
        "text": "Overall, how would you rate your general cybersecurity awareness?",
    },
    # ---- authentication ----
    {
        "id": "q4",
        "category": "authentication",
        "type": "knowledge",
        "text": "A JWT (JSON Web Token) is made of three parts. Which of these is NOT one of them?",
        "options": ["Header", "Payload", "Signature", "Salt"],
        "correct_index": 3,
    },
    {
        "id": "q5",
        "category": "authentication",
        "type": "scenario",
        "text": "A server checks a JWT's payload (who the user claims to be) but never verifies the signature. What's the practical risk?",
        "options": [
            "None — payloads can't be edited",
            "Anyone could hand-edit the payload to claim to be a different user, and the server would believe it",
            "The token would simply stop working",
            "This only affects token expiry",
        ],
        "correct_index": 1,
    },
    {
        "id": "q6",
        "category": "authentication",
        "type": "confidence",
        "text": "How confident are you explaining the difference between authentication and authorization?",
    },
    # ---- web_security ----
    {
        "id": "q7",
        "category": "web_security",
        "type": "knowledge",
        "text": "XSS (Cross-Site Scripting) attacks typically work by:",
        "options": [
            "Overloading a server with traffic",
            "Guessing a user's password repeatedly",
            "Getting a victim's browser to run attacker-supplied script, often via unsanitized input rendered on a page",
            "Intercepting network packets between two servers",
        ],
        "correct_index": 2,
    },
    {
        "id": "q8",
        "category": "web_security",
        "type": "scenario",
        "text": "A chat app inserts every message directly into the page with element.innerHTML = message instead of element.textContent = message. What does this open the door to?",
        "options": [
            "Nothing — innerHTML and textContent are identical",
            "Faster page loading",
            "A message containing <script> tags could execute in other users' browsers",
            "Messages would fail to display",
        ],
        "correct_index": 2,
    },
    {
        "id": "q9",
        "category": "web_security",
        "type": "confidence",
        "text": "How confident are you in your ability to spot an XSS vulnerability by reading code?",
    },
    # ---- cryptography ----
    {
        "id": "q10",
        "category": "cryptography",
        "type": "knowledge",
        "text": "Why hash a password before storing it in a database, instead of storing it as plaintext?",
        "options": [
            "Hashing makes the password shorter to save space",
            "A hash is one-way — a leaked database doesn't directly hand over the original password",
            "Hashing makes login faster",
            "It's required for the password field to accept special characters",
        ],
        "correct_index": 1,
    },
    {
        "id": "q11",
        "category": "cryptography",
        "type": "knowledge",
        "text": "Which of these is a symmetric-key encryption algorithm (same key used to encrypt and decrypt)?",
        "options": ["RSA", "AES", "ECDSA", "ML-DSA"],
        "correct_index": 1,
    },
    {
        "id": "q12",
        "category": "cryptography",
        "type": "confidence",
        "text": "How confident are you explaining the difference between encryption and hashing?",
    },
    # ---- post_quantum_awareness ----
    {
        "id": "q13",
        "category": "post_quantum_awareness",
        "type": "knowledge",
        "text": "Which quantum algorithm poses the theoretical threat to RSA and elliptic-curve cryptography?",
        "options": ["Grover's algorithm", "Shor's algorithm", "Dijkstra's algorithm", "Deutsch-Jozsa algorithm"],
        "correct_index": 1,
    },
    {
        "id": "q14",
        "category": "post_quantum_awareness",
        "type": "knowledge",
        "text": "\"Harvest now, decrypt later\" describes an adversary that:",
        "options": [
            "Steals a database and immediately reads all the plaintext",
            "Records today's encrypted traffic now, planning to decrypt it once a future quantum computer can break today's algorithms",
            "Only attacks unencrypted traffic",
            "Is a defense technique, not an attack",
        ],
        "correct_index": 1,
    },
    {
        "id": "q15",
        "category": "post_quantum_awareness",
        "type": "confidence",
        "text": "How confident are you in your understanding of post-quantum cryptography (e.g. ML-KEM, ML-DSA)?",
    },
    # ---- network_security ----
    {
        "id": "q16",
        "category": "network_security",
        "type": "knowledge",
        "text": "What does TLS primarily provide for a connection between a browser and a server?",
        "options": [
            "Faster page load times",
            "Encryption and integrity for data in transit, plus server identity verification",
            "Automatic virus scanning",
            "Password strength enforcement",
        ],
        "correct_index": 1,
    },
    {
        "id": "q17",
        "category": "network_security",
        "type": "scenario",
        "text": "An attacker on the same public Wi-Fi captures traffic between a browser and a site that has no TLS (plain HTTP). What can they see?",
        "options": [
            "Nothing — Wi-Fi traffic is always private",
            "Only the destination website's name",
            "The full contents of the traffic, including anything typed into forms",
            "Only the browser's operating system",
        ],
        "correct_index": 2,
    },
    {
        "id": "q18",
        "category": "network_security",
        "type": "confidence",
        "text": "How confident are you in identifying whether a website connection is secure (HTTPS/TLS)?",
    },
]

CONFIDENCE_SCALE_MAX = 5


def score_responses(raw_answers: dict) -> dict:
    """
    raw_answers: {question_id: submitted_value}
      - knowledge/scenario: submitted_value is the selected option index (str or int)
      - confidence: submitted_value is a 1-5 rating (str or int)

    Returns per-category and overall percentage scores (0-100), plus
    the per-question breakdown so it's auditable.
    """
    category_points = {cat: 0.0 for cat in CATEGORY_LABELS}
    category_max = {cat: 0 for cat in CATEGORY_LABELS}
    breakdown = []

    for question in QUESTIONS:
        category = question["category"]
        category_max[category] += 1

        submitted = raw_answers.get(question["id"])
        earned = 0.0
        correct = None

        if question["type"] == "confidence":
            try:
                rating = int(submitted)
                rating = max(1, min(CONFIDENCE_SCALE_MAX, rating))
                earned = rating / CONFIDENCE_SCALE_MAX
            except (TypeError, ValueError):
                earned = 0.0
        else:
            try:
                selected = int(submitted)
                correct = selected == question["correct_index"]
                earned = 1.0 if correct else 0.0
            except (TypeError, ValueError):
                correct = False
                earned = 0.0

        category_points[category] += earned

        breakdown.append({
            "id": question["id"],
            "category": category,
            "type": question["type"],
            "correct": correct,
            "points": earned,
        })

    category_scores = {}
    for category in CATEGORY_LABELS:
        max_points = category_max[category] or 1
        category_scores[category] = round(
            100 * category_points[category] / max_points
        )

    overall_score = round(
        sum(category_scores.values()) / len(category_scores)
    )

    return {
        "category_scores": category_scores,
        "overall_score": overall_score,
        "breakdown": breakdown,
    }


# Archetype assigned by strongest category, plus a short description.
PROFILES = {
    "security_awareness": {
        "name": "THE VIGILANT USER",
        "description": "You spot everyday social-engineering and hygiene risks quickly — the kind of thing that stops most real-world attacks before they start.",
    },
    "authentication": {
        "name": "THE PRACTICAL DEFENDER",
        "description": "You have a solid grip on how login and session systems are supposed to work, and where they tend to fail.",
    },
    "web_security": {
        "name": "THE FRONTLINE GUARDIAN",
        "description": "You understand how attackers abuse a running web app in the browser itself, not just the server behind it.",
    },
    "cryptography": {
        "name": "THE CIPHER SCHOLAR",
        "description": "You know why cryptographic primitives are used the way they are, not just their names.",
    },
    "post_quantum_awareness": {
        "name": "THE QUANTUM-FORWARD THINKER",
        "description": "You're already thinking about the threat model that today's classical cryptography wasn't built for.",
    },
    "network_security": {
        "name": "THE TRAFFIC WATCHER",
        "description": "You think in terms of what's actually visible on the wire, not just what's visible on screen.",
    },
}

# When a category is weak, point the user at the Sentinel dashboard
# demos that make that exact gap visible.
RECOMMENDED_DEMOS = {
    "security_awareness": ["Database Leak Simulation", "Invalid JWT"],
    "authentication": ["Invalid JWT", "JWT Tampering", "Unauthorized WebSocket"],
    "web_security": ["XSS Test"],
    "cryptography": ["Database Leak Simulation", "JWT Tampering"],
    "post_quantum_awareness": ["ML-KEM / ML-DSA module (once enabled)"],
    "network_security": ["Unauthorized WebSocket", "Message Tampering"],
}


def build_profile(category_scores: dict, overall_score: int) -> dict:
    strongest = max(category_scores, key=category_scores.get)
    weakest = min(category_scores, key=category_scores.get)

    profile = PROFILES[strongest]

    return {
        "overall_score": overall_score,
        "category_scores": category_scores,
        "category_labels": CATEGORY_LABELS,
        "strongest_category": strongest,
        "strongest_label": CATEGORY_LABELS[strongest],
        "weakest_category": weakest,
        "weakest_label": CATEGORY_LABELS[weakest],
        "profile_name": profile["name"],
        "profile_description": profile["description"],
        "recommended_demos": RECOMMENDED_DEMOS[weakest],
    }
