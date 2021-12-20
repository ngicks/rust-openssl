use std::{
    fs::File,
    io::{BufWriter, Write},
};

use hex;
use openssl::{cms::CmsContentInfo, error::ErrorStack, ts::TsTstInfo};

static RFC3161_HEX: &'static [u8] = include_bytes!("./timstamp_hex.txt");

fn main() -> Result<(), ErrorStack> {
    let decoded = hex::decode(&RFC3161_HEX).unwrap();
    let cms = CmsContentInfo::from_der(&decoded)?;
    let content = cms.get_content()?;

    let mut w = File::create("./tst_info_der")
        .map(|f| BufWriter::new(f))
        .unwrap();

    w.write(&content).unwrap();

    let tst_info = TsTstInfo::from_der(content)?;

    let time = tst_info.get_time()?;

    println!("{}", time.as_utf8()?);

    Ok(())
}
