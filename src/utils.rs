use chrono::Local;
use indicatif::{ProgressBar, ProgressStyle};
use rust_xlsxwriter::ColNum;
use rust_xlsxwriter::{Format, Workbook, XlsxError};
use std::error::Error;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

/// 扫描进度控制结构体
///
/// 封装了进度条功能，支持线程安全的进度更新和消息输出
#[derive(Clone)]
pub struct ScanProgress {
    pb: Arc<ProgressBar>,
}

impl ScanProgress {
    /// 创建新的进度条
    ///
    /// # 参数
    /// * `total` - 总任务数
    ///
    /// # 示例
    /// ```
    /// let progress = ScanProgress::new(100);
    /// ```
    pub fn new(total: u64) -> Self {
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({percent}%) [ETA: {eta}]",
            )
            .unwrap()
            .progress_chars("█▓▒░ "),
        );
        Self { pb: Arc::new(pb) }
    }

    /// 进度增加指定数量
    ///
    /// # 参数
    /// * `delta` - 增加的数量，默认为1
    pub fn inc(&self, delta: u64) {
        self.pb.inc(delta);
    }

    /// 在进度条上方输出信息（不会破坏进度条显示）
    ///
    /// # 参数
    /// * `msg` - 要输出的消息
    pub fn println<S: AsRef<str>>(&self, msg: S) {
        self.pb.println(msg.as_ref());
    }

    /// 设置进度条消息
    ///
    /// # 参数
    /// * `msg` - 消息内容
    pub fn set_message<S: Into<String>>(&self, msg: S) {
        self.pb.set_message(msg.into());
    }

    /// 完成并关闭进度条
    pub fn finish(&self) {
        self.pb.finish_with_message("✅ 扫描完成");
    }

    /// 完成进度条并显示自定义消息
    ///
    /// # 参数
    /// * `msg` - 完成时显示的消息
    pub fn finish_with_message<S: Into<String>>(&self, msg: S) {
        self.pb.finish_with_message(msg.into());
    }
}

/// 确保输出目录存在，如不存在则创建
///
/// # 参数
/// * `path` - 目录路径
///
/// # 返回
/// * `Ok(PathBuf)` - 目录的完整路径
/// * `Err` - 创建失败时返回错误
///
/// # 示例
/// ```
/// let output_dir = ensure_output_dir("output/scan")?;
/// ```
pub fn ensure_output_dir(path: &str) -> Result<PathBuf, Box<dyn Error + Send + Sync>> {
    let output_dir = PathBuf::from(path);
    if !output_dir.exists() {
        fs::create_dir_all(&output_dir).map_err(|e| format!("创建目录失败 {}: {}", path, e))?;
    }
    Ok(output_dir)
}

/// 检查文件是否存在
///
/// # 参数
/// * `file_path` - 文件路径
///
/// # 返回
/// * `true` - 文件存在
/// * `false` - 文件不存在
#[inline]
pub fn check_file_exists(file_path: &Path) -> bool {
    file_path.exists() && file_path.is_file()
}

/// 创建Excel模板文件（仅包含表头）
///
/// # 参数
/// * `path` - Excel文件路径
/// * `headers` - 表头列表
///
/// # 返回
/// * `Ok(())` - 创建成功
/// * `Err(XlsxError)` - 创建失败
///
/// # 示例
/// ```
/// create_excel_template(
///     "output/template.xlsx",
///     vec!["IP地址".to_string(), "端口".to_string(), "状态".to_string()]
/// )?;
/// ```
pub fn create_excel_template<P: AsRef<Path>>(
    path: P,
    headers: Vec<String>,
) -> Result<(), XlsxError> {
    let mut workbook = Workbook::new(path.as_ref().to_str().unwrap());
    let worksheet = workbook.add_worksheet();

    // 创建表头格式（加粗）
    let header_format = Format::new().set_bold();

    // 写入表头
    for (col_num, header) in headers.iter().enumerate() {
        worksheet.write_string(0, col_num as u16, header, &header_format)?;
    }

    workbook.close()?;
    Ok(())
}

/// 解析目标IP地址字符串，支持多种格式
///
/// 支持的格式：
/// - 单个IP: `192.168.1.1`
/// - 多个IP（逗号分隔）: `192.168.1.1,192.168.1.2`
/// - IP范围: `192.168.1.1-10`
/// - CIDR: `192.168.1.0/24`
///
/// # 参数
/// * `targets` - 目标字符串
///
/// # 返回
/// * `Ok(Vec<String>)` - 解析后的IP地址列表
/// * `Err` - 解析失败时返回错误信息
///
/// # 示例
/// ```
/// let ips = parse_targets("192.168.1.0/24,10.0.0.1-5")?;
/// ```
pub fn parse_targets(targets: &str) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    let mut all_ips = Vec::new();

    for target in targets.split(',') {
        let target = target.trim();

        if target.is_empty() {
            continue;
        }

        if target.contains('/') {
            // CIDR格式：192.168.1.0/24
            let cidr_ips = parse_cidr(target)?;
            all_ips.extend(cidr_ips);
        } else if target.contains('-') {
            // IP范围格式：192.168.1.1-10
            let range_ips = parse_ip_range(target)?;
            all_ips.extend(range_ips);
        } else {
            // 单个IP地址
            Ipv4Addr::from_str(target).map_err(|_| format!("无效的IP地址: {}", target))?;
            all_ips.push(target.to_string());
        }
    }

    if all_ips.is_empty() {
        return Err("未解析到任何有效的IP地址".into());
    }

    Ok(all_ips)
}

/// 从CIDR格式解析IP地址列表
///
/// # 参数
/// * `cidr` - CIDR格式字符串，如 "192.168.1.0/24"
///
/// # 返回
/// * `Ok(Vec<String>)` - IP地址列表（不包含网络地址和广播地址）
/// * `Err` - 解析失败
fn parse_cidr(cidr: &str) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    // 分割IP和子网掩码
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("无效的CIDR格式: {}", cidr).into());
    }

    let ip_str = parts[0];
    let prefix_len_str = parts[1];

    // 解析IP和子网掩码长度
    let ip = Ipv4Addr::from_str(ip_str).map_err(|_| format!("CIDR中的IP地址无效: {}", ip_str))?;
    let prefix_len: u8 = prefix_len_str
        .parse()
        .map_err(|_| format!("无效的子网掩码长度: {}", prefix_len_str))?;

    if prefix_len > 32 {
        return Err("子网掩码长度不能超过32".into());
    }

    // 将IP转换为u32整数（方便计算）
    let ip_int = u32::from(ip);
    // 计算子网掩码的整数形式
    let mask = if prefix_len == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix_len)
    };

    // 计算网络地址（IP & 子网掩码）
    let network_int = ip_int & mask;
    // 计算广播地址（网络地址 | 反掩码）
    let broadcast_int = network_int | !mask;

    // 转换回Ipv4Addr
    let _network_ip = Ipv4Addr::from(network_int);
    let _broadcast_ip = Ipv4Addr::from(broadcast_int);

    // 遍历网络地址+1 到 广播地址-1（可用IP范围）
    let mut ips = Vec::new();
    let mut current_int = network_int + 1;

    // 避免循环溢出（比如/31、/32网段）
    if network_int >= broadcast_int - 1 {
        return Err(format!("CIDR {} 没有可用的主机IP", cidr).into());
    }

    while current_int < broadcast_int {
        let current_ip = Ipv4Addr::from(current_int);
        ips.push(current_ip.to_string());
        current_int += 1;
    }

    Ok(ips)
}

/// 从IP范围格式解析IP地址列表
///
/// # 参数
/// * `range_str` - IP范围字符串，如 "192.168.1.1-10"
///
/// # 返回
/// * `Ok(Vec<String>)` - IP地址列表
/// * `Err` - 解析失败
fn parse_ip_range(range_str: &str) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    let dash_pos = range_str
        .rfind('-')
        .ok_or_else(|| format!("无效的IP范围格式: {}", range_str))?;

    let (base, end) = range_str.split_at(dash_pos);
    let base_ip =
        Ipv4Addr::from_str(base.trim()).map_err(|_| format!("无效的起始IP地址: {}", base))?;

    let end_part = end[1..].trim();
    let end_last = end_part
        .parse::<u8>()
        .map_err(|_| format!("IP范围结束值无效: {}", end_part))?;

    let base_parts = base_ip.octets();

    if end_last < base_parts[3] {
        return Err(format!(
            "IP范围结束值({})必须大于或等于起始值({})",
            end_last, base_parts[3]
        )
        .into());
    }

    let mut ips = Vec::new();
    for i in base_parts[3]..=end_last {
        let ip = Ipv4Addr::new(base_parts[0], base_parts[1], base_parts[2], i);
        ips.push(ip.to_string());
    }

    Ok(ips)
}

/// 将数据保存到Excel文件
///
/// # 类型参数
/// * `T` - 数据项类型
/// * `F` - 行映射函数类型
///
/// # 参数
/// * `data` - 要保存的数据切片
/// * `headers` - 表头列表
/// * `row_mapper` - 将数据项映射为字符串向量的函数
/// * `subdir` - 输出子目录名称
/// * `filename_prefix` - 文件名前缀
///
/// # 返回
/// * `Ok(String)` - 保存的文件路径
/// * `Err` - 保存失败
///
/// # 示例
/// ```
/// save_to_excel(
///     &results,
///     &["IP", "状态"],
///     |r| vec![r.ip.clone(), r.status.clone()],
///     "scan",
///     "result"
/// )?;
/// ```
pub fn save_to_excel<T, F>(
    data: &[T],
    headers: &[&str],
    row_mapper: F,
    subdir: &str,
    filename_prefix: &str,
) -> Result<String, Box<dyn Error + Send + Sync>>
where
    F: Fn(&T) -> Vec<String>,
{
    let output_dir = ensure_output_dir(&format!("output/{}", subdir))?;

    let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let filename = format!("{}_{}.xlsx", filename_prefix, timestamp);
    let filepath = output_dir.join(&filename);

    let mut workbook = Workbook::new(filepath.to_str().unwrap());
    let worksheet = workbook.add_worksheet();

    // 表头格式
    let header_format = Format::new().set_bold();

    // 普通单元格格式
    let cell_format = Format::new();

    // 写入表头
    for (col, header) in headers.iter().enumerate() {
        worksheet.write_string(0, ColNum::from(col as u16), header, &header_format)?;
    }

    // 写入数据
    for (i, item) in data.iter().enumerate() {
        let row_data = row_mapper(item);
        for (j, value) in row_data.iter().enumerate() {
            worksheet.write_string((i + 1) as u32, ColNum::from(j as u16), value, &cell_format)?;
        }
    }

    workbook.close()?;
    println!("✅ 结果已保存至: output/{}/{}", subdir, filename);
    Ok(filepath.to_string_lossy().to_string())
}

/// 解析端口字符串，支持单个端口、范围和混合格式
///
/// 支持的格式：
/// - 单个端口: `80`
/// - 多个端口: `80,443,8080`
/// - 端口范围: `80-90`
/// - 混合格式: `22,80-443,8000-9000`
///
/// # 参数
/// * `port_str` - 端口字符串
///
/// # 返回
/// * `Vec<u16>` - 解析后的端口列表（已排序去重）
///
/// # 示例
/// ```
/// let ports = parse_ports("22,80-443,8080");
/// ```
pub fn parse_ports(port_str: &str) -> Vec<u16> {
    let mut ports = Vec::new();

    for part in port_str.split(',') {
        let part = part.trim();

        if part.is_empty() {
            continue;
        }

        if part.contains('-') {
            // 端口范围：80-443
            if let Some((start_str, end_str)) = part.split_once('-') {
                if let (Ok(start), Ok(end)) = (
                    start_str.trim().parse::<u16>(),
                    end_str.trim().parse::<u16>(),
                ) {
                    if start <= end {
                        ports.extend(start..=end);
                    } else {
                        eprintln!("⚠️  无效的端口范围: {}", part);
                    }
                }
            }
        } else {
            // 单个端口
            if let Ok(port) = part.parse::<u16>() {
                ports.push(port);
            } else {
                eprintln!("⚠️  无效的端口号: {}", part);
            }
        }
    }

    // 排序并去重
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// 格式化字节大小为人类可读格式
///
/// # 参数
/// * `bytes` - 字节数
///
/// # 返回
/// * `String` - 格式化后的字符串，如 "1.5 MB"
///
/// # 示例
/// ```
/// let size = format_bytes(1048576); // "1.00 MB"
/// ```
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_index])
}

/// 格式化持续时间为人类可读格式
///
/// # 参数
/// * `duration` - 持续时间（秒）
///
/// # 返回
/// * `String` - 格式化后的字符串，如 "1h 23m 45s"
pub fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, secs)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_ip() {
        let result = parse_targets("192.168.1.1").unwrap();
        assert_eq!(result, vec!["192.168.1.1"]);
    }

    #[test]
    fn test_parse_ip_range() {
        let result = parse_targets("192.168.1.1-3").unwrap();
        assert_eq!(result, vec!["192.168.1.1", "192.168.1.2", "192.168.1.3"]);
    }

    #[test]
    fn test_parse_cidr() {
        let result = parse_targets("192.168.1.0/30").unwrap();
        assert_eq!(result, vec!["192.168.1.1", "192.168.1.2"]);
    }

    #[test]
    fn test_parse_ports() {
        let result = parse_ports("22,80-82,443");
        assert_eq!(result, vec![22, 80, 81, 82, 443]);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(3661), "1h 1m 1s");
        assert_eq!(format_duration(65), "1m 5s");
        assert_eq!(format_duration(30), "30s");
    }
}
