use std::sync::mpsc::Receiver;
use std::time::Instant;
use wgpu::util::DeviceExt;

use crate::{WorkerCommand, WorkerUpdate, get_worker_channel};

pub fn crack_hash_gpu(
    target_hash: String,
    charset: String,
    min_length: usize,
    max_length: usize,
    cmd_rx: Receiver<WorkerCommand>,
) {
    let (update_tx, _) = get_worker_channel();

    // Initialize wgpu
    let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
        backends: wgpu::Backends::all(),
        ..Default::default()
    });

    // Request adapter
    let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
        power_preference: wgpu::PowerPreference::HighPerformance,
        force_fallback_adapter: false,
        compatible_surface: None,
    }));

    let adapter = match adapter {
        Some(a) => a,
        None => {
            let _ = update_tx.send(WorkerUpdate::Progress {
                current_attempt: String::from("ERROR: No GPU adapter found"),
                attempts_count: 0,
            });
            return;
        }
    };

    // Get device and queue
    let (device, queue) = match pollster::block_on(adapter.request_device(
        &wgpu::DeviceDescriptor {
            label: Some("SHA256 Cracker Device"),
            required_features: wgpu::Features::empty(),
            required_limits: wgpu::Limits::default(),
        },
        None,
    )) {
        Ok(dq) => dq,
        Err(e) => {
            let _ = update_tx.send(WorkerUpdate::Progress {
                current_attempt: format!("ERROR: Failed to get device: {}", e),
                attempts_count: 0,
            });
            return;
        }
    };

    let adapter_info = adapter.get_info();
    let _ = update_tx.send(WorkerUpdate::Progress {
        current_attempt: format!(
            "GPU initialized: {} (Backend: {:?})",
            adapter_info.name, adapter_info.backend
        ),
        attempts_count: 0,
    });

    // Parse target hash from hex string to u32 array
    let target_hash_bytes = match hex_to_u32_array(&target_hash) {
        Ok(bytes) => bytes,
        Err(_) => {
            let _ = update_tx.send(WorkerUpdate::Progress {
                current_attempt: String::from("ERROR: Invalid hash format"),
                attempts_count: 0,
            });
            return;
        }
    };

    // Convert charset to u32 array (ASCII values)
    let charset_bytes: Vec<u32> = charset.chars().map(|c| c as u32).collect();
    let charset_size = charset_bytes.len() as u32;

    // Load shader
    let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("SHA256 Shader"),
        source: wgpu::ShaderSource::Wgsl(include_str!("shaders/sha256.wgsl").into()),
    });

    // Create buffers and pipeline
    let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: Some("Bind Group Layout"),
        entries: &[
            wgpu::BindGroupLayoutEntry {
                binding: 0,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 1,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 2,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: false },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
        ],
    });

    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: Some("Pipeline Layout"),
        bind_group_layouts: &[&bind_group_layout],
        push_constant_ranges: &[],
    });

    let compute_pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some("Compute Pipeline"),
        layout: Some(&pipeline_layout),
        module: &shader,
        entry_point: "main",
    });

    // Create charset buffer
    let charset_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("Charset Buffer"),
        contents: bytemuck::cast_slice(&charset_bytes),
        usage: wgpu::BufferUsages::STORAGE,
    });

    let mut total_attempts = 0u64;
    let mut last_update_time = Instant::now();

    const BATCH_SIZE: u32 = 1024 * 256; // Process 256K hashes per batch

    // Iterate through each length
    for current_length in min_length..=max_length {
        let _ = update_tx.send(WorkerUpdate::Progress {
            current_attempt: format!("GPU searching length {}...", current_length),
            attempts_count: total_attempts,
        });

        // Calculate total combinations for this length
        let total_for_length = charset_size.pow(current_length as u32) as u64;
        let mut start_index = 0u64;

        while start_index < total_for_length {
            // Check for stop command
            if let Ok(WorkerCommand::Stop) = cmd_rx.try_recv() {
                return;
            }

            let batch_size = BATCH_SIZE.min((total_for_length - start_index) as u32);

            // Create params buffer
            let params_data = SearchParams {
                target_hash: target_hash_bytes,
                start_index: start_index as u32,
                batch_size,
                charset_size,
                string_length: current_length as u32,
            };

            let params_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some("Params Buffer"),
                contents: bytemuck::bytes_of(&params_data),
                usage: wgpu::BufferUsages::STORAGE,
            });

            // Create results buffer (10 u32s: [found_flag, index, hash[8]])
            let results_data = vec![0u32; 10];
            let results_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some("Results Buffer"),
                contents: bytemuck::cast_slice(&results_data),
                usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            });

            // Create staging buffer for reading results
            let staging_buffer = device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("Staging Buffer"),
                size: (results_data.len() * 4) as u64,
                usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });

            // Create bind group
            let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some("Bind Group"),
                layout: &bind_group_layout,
                entries: &[
                    wgpu::BindGroupEntry {
                        binding: 0,
                        resource: params_buffer.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 1,
                        resource: charset_buffer.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 2,
                        resource: results_buffer.as_entire_binding(),
                    },
                ],
            });

            // Create command encoder and dispatch compute
            let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("Compute Encoder"),
            });

            {
                let mut compute_pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                    label: Some("Compute Pass"),
                    timestamp_writes: None,
                });
                compute_pass.set_pipeline(&compute_pipeline);
                compute_pass.set_bind_group(0, &bind_group, &[]);
                let workgroups = (batch_size + 255) / 256; // 256 threads per workgroup
                compute_pass.dispatch_workgroups(workgroups, 1, 1);
            }

            // Copy results to staging buffer
            encoder.copy_buffer_to_buffer(
                &results_buffer,
                0,
                &staging_buffer,
                0,
                (results_data.len() * 4) as u64,
            );

            queue.submit(Some(encoder.finish()));

            // Read results
            let buffer_slice = staging_buffer.slice(..);
            let (sender, receiver) = futures::channel::oneshot::channel();
            buffer_slice.map_async(wgpu::MapMode::Read, move |result| {
                sender.send(result).unwrap();
            });

            device.poll(wgpu::Maintain::Wait);
            pollster::block_on(receiver).unwrap().unwrap();

            let data = buffer_slice.get_mapped_range();
            let results: &[u32] = bytemuck::cast_slice(&data);

            // Check if found
            if results[0] == 1 {
                let found_index = results[1] as u64;
                let found_string = index_to_string(found_index, current_length, &charset);

                let _ = update_tx.send(WorkerUpdate::Found {
                    match_string: found_string,
                    attempts_count: total_attempts + found_index,
                });

                return;
            }

            drop(data);
            staging_buffer.unmap();

            total_attempts += batch_size as u64;
            start_index += batch_size as u64;

            // Send progress update every 100ms
            if last_update_time.elapsed().as_millis() >= 100 {
                let candidate =
                    index_to_string(start_index.saturating_sub(1), current_length, &charset);
                let _ = update_tx.send(WorkerUpdate::Progress {
                    current_attempt: candidate,
                    attempts_count: total_attempts,
                });
                last_update_time = Instant::now();
            }
        }
    }

    // No match found
    let _ = update_tx.send(WorkerUpdate::Progress {
        current_attempt: String::from("GPU search completed - no match found"),
        attempts_count: total_attempts,
    });
}

#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
struct SearchParams {
    target_hash: [u32; 8],
    start_index: u32,
    batch_size: u32,
    charset_size: u32,
    string_length: u32,
}

fn hex_to_u32_array(hex: &str) -> Result<[u32; 8], ()> {
    if hex.len() != 64 {
        return Err(());
    }

    let mut result = [0u32; 8];
    for i in 0..8 {
        let start = i * 8;
        let end = start + 8;
        result[i] = u32::from_str_radix(&hex[start..end], 16).map_err(|_| ())?;
    }

    Ok(result)
}

fn index_to_string(mut idx: u64, length: usize, charset: &str) -> String {
    let chars: Vec<char> = charset.chars().collect();
    let charset_size = chars.len() as u64;
    let mut result = vec!['a'; length];

    for i in 0..length {
        result[i] = chars[(idx % charset_size) as usize];
        idx /= charset_size;
    }

    result.into_iter().collect()
}
