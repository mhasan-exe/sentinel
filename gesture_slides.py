"""
gesture_slides.py

Standalone hand-gesture slide controller for the live Sentinel demo.
This is NOT part of the FastAPI app — it's a separate desktop script
you run locally (it needs your webcam and an actual display), per
spec section 7: gesture recognition is an interaction/navigation
layer, not something the browser itself can do without WebRTC.

HOW IT WORKS
------------
1. Opens your webcam and watches one hand with cvzone's HandDetector
   (built on MediaPipe).
2. Counts how many fingers are up (0-5).
3. Open palm (5 fingers)  -> presses the Right arrow key -> next slide
   Closed fist (0 fingers) -> presses the Left arrow key  -> previous slide
4. A short cooldown after each trigger stops one gesture from firing
   ten times in a row while your hand is still in frame.

WHAT IT CONTROLS
----------------
Arrow-key presses go to whatever window currently has OS focus. Two
ways to use that:
  (a) Open http://<host>/presentation in a browser (the route this
      project's main.py serves) and click into that tab first — it
      already listens for ArrowLeft/ArrowRight (see presentation.html).
  (b) Open the actual .pptx in PowerPoint / Slide Show mode, or the
      PDF in any viewer that supports arrow-key navigation, and click
      into that window first. This script doesn't care which one has
      focus — it just sends the keystroke.

SETUP
-----
This needs a separate, heavier dependency set than the web app (a
webcam, OpenCV, MediaPipe) — install these on the machine you'll
actually demo from, not necessarily the server:

    pip install cvzone opencv-python mediapipe pyautogui

Then just run it:

    python gesture_slides.py

Press 'q' with the camera window focused to quit.
"""

import time

import cv2
import pyautogui
from cvzone.HandTrackingModule import HandDetector

# --- tunables -----------------------------------------------------------

CAMERA_INDEX = 0          # change if you have multiple webcams
DETECTION_CONFIDENCE = 0.8
COOLDOWN_SECONDS = 1.2    # minimum time between two triggered slide changes
OPEN_PALM_FINGERS = 5     # all fingers up
CLOSED_FIST_FINGERS = 0   # no fingers up


def main():
    cap = cv2.VideoCapture(CAMERA_INDEX)
    if not cap.isOpened():
        raise RuntimeError(
            f"Could not open webcam at index {CAMERA_INDEX}. "
            "Check CAMERA_INDEX or that no other app is using the camera."
        )

    detector = HandDetector(maxHands=1, detectionCon=DETECTION_CONFIDENCE)

    last_trigger_time = 0.0
    last_action_label = ""

    print("Gesture slide controller running.")
    print("Open palm = next slide | Fist = previous slide | 'q' to quit.")
    print("Click into the presentation window/tab before gesturing.")

    while True:
        success, frame = cap.read()
        if not success:
            print("Failed to read from webcam — stopping.")
            break

        hands, frame = detector.findHands(frame, draw=True)

        now = time.time()
        cooldown_remaining = max(0.0, COOLDOWN_SECONDS - (now - last_trigger_time))

        if hands and cooldown_remaining == 0.0:
            hand = hands[0]
            fingers = detector.fingersUp(hand)
            fingers_up_count = sum(fingers)

            if fingers_up_count == OPEN_PALM_FINGERS:
                pyautogui.press("right")
                last_trigger_time = now
                last_action_label = "NEXT SLIDE ->"
                print(last_action_label)

            elif fingers_up_count == CLOSED_FIST_FINGERS:
                pyautogui.press("left")
                last_trigger_time = now
                last_action_label = "<- PREV SLIDE"
                print(last_action_label)

        # --- on-screen overlay so you can see what it's detecting while presenting ---
        status_text = (
            f"cooldown {cooldown_remaining:.1f}s"
            if cooldown_remaining > 0
            else "ready"
        )
        cv2.putText(
            frame,
            f"Sentinel Gesture Control - {status_text}",
            (10, 30),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.7,
            (0, 255, 0),
            2,
        )
        if last_action_label:
            cv2.putText(
                frame,
                last_action_label,
                (10, 60),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.8,
                (0, 165, 255),
                2,
            )

        cv2.imshow("Sentinel Gesture Control (press q to quit)", frame)

        if cv2.waitKey(1) & 0xFF == ord("q"):
            break

    cap.release()
    cv2.destroyAllWindows()


if __name__ == "__main__":
    main()
