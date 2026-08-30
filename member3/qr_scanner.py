import cv2
from pyzbar.pyzbar import decode

from pipeline import process_url


def scan_qr():

    camera = cv2.VideoCapture(0)

    if not camera.isOpened():

        print("Could not access camera.")
        return

    print("QR Scanner started.")
    print("Show a QR code to the camera.")
    print("Press 'q' to quit.")

    while True:

        success, frame = camera.read()

        if not success:

            print("Could not read camera frame.")
            break

        decoded_objects = decode(frame)

        for obj in decoded_objects:

            data = obj.data.decode("utf-8").strip()

            print("\nQR data:", data)

            # Send QR data into security pipeline
            result = process_url(data)

            print("Processed Result:")
            print(result)

        cv2.imshow("QR Scanner", frame)

        if cv2.waitKey(1) & 0xFF == ord("q"):
            break

    camera.release()
    cv2.destroyAllWindows()


if __name__ == "__main__":
    scan_qr()