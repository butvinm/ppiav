// 6-step image preprocessing pipeline (browser side).
// Mirrors models/prepare_samples.py: decode → resize 64x64 → RGB → normalize
// to [-1, 1] → HWC→CHW → Float64Array of length 3*64*64 = 12288.
//
// Canvas resize is browser-defined and drifts from Pillow by sub-1/255 per
// pixel; the C3AE decision boundary tolerates this (see plan's "No
// byte-equivalence requirement" note).

export async function preprocessImage(file: File): Promise<Float64Array> {
  const url = URL.createObjectURL(file);
  try {
    const img = new Image();
    await new Promise<void>((resolve, reject) => {
      img.onload = () => resolve();
      img.onerror = () => reject(new Error("image decode failed"));
      img.src = url;
    });

    const canvas = document.createElement("canvas");
    canvas.width = 64;
    canvas.height = 64;
    const ctx = canvas.getContext("2d");
    if (ctx === null) {
      throw new Error("2d canvas context unavailable");
    }
    ctx.drawImage(img, 0, 0, 64, 64);
    const rgba = ctx.getImageData(0, 0, 64, 64).data;

    const hw = 64 * 64;
    const tensor = new Float64Array(3 * hw);
    for (let i = 0; i < hw; i++) {
      tensor[i] = (rgba[4 * i] / 255 - 0.5) / 0.5;
      tensor[hw + i] = (rgba[4 * i + 1] / 255 - 0.5) / 0.5;
      tensor[2 * hw + i] = (rgba[4 * i + 2] / 255 - 0.5) / 0.5;
    }
    return tensor;
  } finally {
    URL.revokeObjectURL(url);
  }
}
