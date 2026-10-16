"""Request path through the guardrails. `layers` selects which ones are on, so the harness can ablate them."""

import time

from .guards import filter_output, match_input_rules, scrub_pii
from .target import user_message

ALL_LAYERS = ("rules", "classifier", "pii_scrub", "output_filter")
CONFIGS = {
    "none": (),
    "rules": ("rules",),
    "rules+classifier": ("rules", "classifier"),
    "full": ALL_LAYERS,
}
REFUSAL = "Sorry, I can't help with that request."


def handle(target, classifier, user_input: str, document: str | None = None, layers=ALL_LAYERS, sim_goal=None) -> dict:
    t0 = time.perf_counter()
    full_text = user_message(user_input, document)

    def done(response, blocked_by=None, stage="input"):
        return {
            "response": response,
            "blocked": blocked_by is not None and not blocked_by.endswith("pii_redacted"),
            "blocked_by": blocked_by,
            "stage": stage if blocked_by else None,
            "latency_ms": (time.perf_counter() - t0) * 1000,
        }

    if "rules" in layers and (rule := match_input_rules(full_text)):
        return done(REFUSAL, f"rule:{rule}")
    if "classifier" in layers and classifier.is_attack(full_text):
        return done(REFUSAL, "classifier")
    if "pii_scrub" in layers:
        user_input, _ = scrub_pii(user_input)
        document = scrub_pii(document)[0] if document else document

    reply = target.respond(user_input, document, sim_goal=sim_goal)
    if "output_filter" in layers:
        text, reason = filter_output(reply.text)
        if reason:
            return done(text, f"output:{reason}", stage="output")
    return done(reply.text)
