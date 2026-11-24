use qrcodegen::{QrCode, QrCodeEcc};

use crate::error::AppError;

/// Render a profile as an RGBA PNG QR code (5 px per module, 4 module border).
pub fn profile_png(content: &str) -> Result<Vec<u8>, AppError> {
    let code = QrCode::encode_text(content, QrCodeEcc::Medium)
        .map_err(|error| AppError::runtime(format!("Could not create QR code: {error}")))?;
    let border: u32 = 4;
    let scale: u32 = 5;
    let modules = code.size() as u32;
    let size = (modules + border * 2) * scale;
    let mut pixels = vec![0_u8; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let offset = ((y * size + x) * 4) as usize;
            pixels[offset + 3] = 0;
        }
    }
    for module_y in 0..modules {
        for module_x in 0..modules {
            if !code.get_module(module_x as i32, module_y as i32) {
                continue;
            }
            for dy in 0..scale {
                for dx in 0..scale {
                    let x = (module_x + border) * scale + dx;
                    let y = (module_y + border) * scale + dy;
                    let offset = ((y * size + x) * 4) as usize;
                    pixels[offset] = 0;
                    pixels[offset + 1] = 0;
                    pixels[offset + 2] = 0;
                    pixels[offset + 3] = 255;
                }
            }
        }
    }
    let mut output = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut output, size, size);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder
            .write_header()
            .map_err(|error| AppError::runtime(format!("Could not encode QR code: {error}")))?;
        writer
            .write_image_data(&pixels)
            .map_err(|error| AppError::runtime(format!("Could not encode QR code: {error}")))?;
    }
    Ok(output)
}
