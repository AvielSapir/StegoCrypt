import sys
import argparse
from PIL import Image
from stego import StegoEngine

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["embed", "extract"])
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", default="stego_output.png")
    parser.add_argument("--passphrase", required=True)
    parser.add_argument("--message", default=None)
    parser.add_argument("--file", default=None)
    args = parser.parse_args()

    if args.mode == "embed":
        if args.file:
            with open(args.file, "rb") as f:
                payload = f.read()
        elif args.message:
            payload = args.message.encode("utf-8")
        else:
            print("[ERROR] Must provide --message or --file to embed.")
            return

        carrier = Image.open(args.image)
        result_img = StegoEngine.embed(carrier, payload, args.passphrase)
        result_img.save(args.output, "PNG")
        print(f"[SUCCESS] Embedded {len(payload)} bytes into {args.output}")

    elif args.mode == "extract":
        carrier = Image.open(args.image)
        try:
            extracted_data = StegoEngine.extract(carrier, args.passphrase)
            if args.output and args.output != "stego_output.png":
                with open(args.output, "wb") as f:
                    f.write(extracted_data)
                print(f"[SUCCESS] Extracted {len(extracted_data)} bytes to {args.output}")
            else:
                try:
                    text = extracted_data.decode("utf-8")
                    print(f"[EXTRACTED MESSAGE] {text}")
                except UnicodeDecodeError:
                    print(f"[SUCCESS] Extracted binary payload of {len(extracted_data)} bytes.")
        except Exception as err:
            print(f"[ERROR] Extraction failed: {err}")

if __name__ == "__main__":
    main()
