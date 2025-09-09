// 邮件管理相关功能

// 全局变量
let mailHistory = [];
let currentPage = 1;
let pageSize = 50;

// 刷新邮件历史
async function refreshMailHistory() {
    const tbody = document.getElementById('mail-history-body');
    tbody.innerHTML = '<tr><td colspan="8" class="text-center"><i class="fas fa-spinner fa-spin"></i> 加载中...</td></tr>';
    
    try {
        const response = await fetch('/api/v1/mail/history?page=' + currentPage + '&page_size=' + pageSize);
        const data = await response.json();
        
        if (data.success) {
            displayMailHistory(data.data);
        } else {
            showError('获取邮件历史失败: ' + data.error);
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-danger">获取数据失败</td></tr>';
        }
    } catch (error) {
        console.error('Error:', error);
        showError('网络请求失败');
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-danger">网络请求失败</td></tr>';
    }
}

// 显示邮件历史
function displayMailHistory(data) {
    const tbody = document.getElementById('mail-history-body');
    
    if (!data || !data.records || data.records.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-4"><i class="fas fa-envelope fa-2x mb-2"></i><br>暂无邮件记录</td></tr>';
        return;
    }
    
    mailHistory = data.records;
    let html = '';
    
    data.records.forEach(mail => {
        const statusBadge = getStatusBadge(mail.status);
        const directionBadge = getDirectionBadge(mail.direction);
        const formattedDate = new Date(mail.timestamp).toLocaleString('zh-CN');
        const sizeFormatted = formatBytes(mail.size);
        
        html += `
            <tr>
                <td>${formattedDate}</td>
                <td title="${mail.from}">${truncateString(mail.from, 20)}</td>
                <td title="${mail.to.join(', ')}">${truncateString(mail.to.join(', '), 20)}</td>
                <td title="${mail.subject}">${truncateString(mail.subject, 30)}</td>
                <td>${statusBadge}</td>
                <td>${directionBadge}</td>
                <td>${sizeFormatted}</td>
                <td>
                    <div class="btn-group btn-group-sm">
                        <button class="btn btn-outline-info" onclick="viewMailDetail('${mail.id}')" title="查看详情">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="btn btn-outline-success" onclick="downloadEML('${mail.id}')" title="下载EML">
                            <i class="fas fa-download"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
}

// 搜索邮件
async function searchMails() {
    const startDate = document.getElementById('search-start-date').value;
    const endDate = document.getElementById('search-end-date').value;
    
    let url = '/api/v1/mail/search?limit=100';
    if (startDate) url += '&start_date=' + startDate;
    if (endDate) url += '&end_date=' + endDate;
    
    const tbody = document.getElementById('mail-history-body');
    tbody.innerHTML = '<tr><td colspan="8" class="text-center"><i class="fas fa-spinner fa-spin"></i> 搜索中...</td></tr>';
    
    try {
        const response = await fetch(url);
        const data = await response.json();
        
        if (data.success) {
            displaySearchResults(data.data);
        } else {
            showError('搜索失败: ' + data.error);
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-danger">搜索失败</td></tr>';
        }
    } catch (error) {
        console.error('Error:', error);
        showError('搜索请求失败');
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-danger">搜索请求失败</td></tr>';
    }
}

// 显示搜索结果
function displaySearchResults(messages) {
    const tbody = document.getElementById('mail-history-body');
    
    if (!messages || messages.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-4"><i class="fas fa-search fa-2x mb-2"></i><br>未找到匹配的邮件</td></tr>';
        return;
    }
    
    displayMailHistory({ records: messages });
}

// 发送邮件
async function sendMail(event) {
    event.preventDefault();
    
    const form = document.getElementById('send-mail-form');
    const submitBtn = form.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    
    // 获取表单数据
    const mailData = {
        from: document.getElementById('mail-from').value.trim(),
        to: document.getElementById('mail-to').value.trim(),
        subject: document.getElementById('mail-subject').value.trim(),
        body: document.getElementById('mail-body').value.trim()
    };
    
    // 验证表单
    if (!mailData.from || !mailData.to || !mailData.subject || !mailData.body) {
        showError('请填写所有必填字段');
        return;
    }
    
    // 禁用提交按钮
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 发送中...';
    submitBtn.disabled = true;
    
    try {
        const response = await fetch('/api/v1/mail/send', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(mailData)
        });
        
        const data = await response.json();
        
        if (data.success) {
            showSuccess('邮件发送成功！');
            form.reset();
            // 刷新邮件历史
            setTimeout(() => {
                refreshMailHistory();
            }, 1000);
        } else {
            showError('发送失败: ' + data.error);
        }
    } catch (error) {
        console.error('Error:', error);
        showError('发送请求失败');
    } finally {
        // 恢复提交按钮
        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
    }
}

// 清空邮件表单
function clearMailForm() {
    document.getElementById('send-mail-form').reset();
}

// 查看邮件详情
async function viewMailDetail(messageId) {
    try {
        const response = await fetch(`/api/v1/mail/history/${messageId}`);
        const data = await response.json();
        
        if (data.success) {
            showMailDetailModal(data.data);
        } else {
            showError('获取邮件详情失败: ' + data.error);
        }
    } catch (error) {
        console.error('Error:', error);
        showError('获取邮件详情失败');
    }
}

// 下载EML文件
function downloadEML(messageId) {
    const link = document.createElement('a');
    link.href = `/api/v1/mail/history/${messageId}/download`;
    link.download = `mail_${messageId}.eml`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// 获取邮件服务器状态
async function getMailServerStatus() {
    try {
        const response = await fetch('/api/v1/mail/status');
        const data = await response.json();
        
        if (data.success) {
            displayMailServerStatus(data.data);
        } else {
            showError('获取邮件服务状态失败: ' + data.error);
        }
    } catch (error) {
        console.error('Error:', error);
        showError('获取邮件服务状态失败');
    }
}

// 显示邮件服务器状态
function displayMailServerStatus(status) {
    const serverStatusDiv = document.getElementById('mail-server-status');
    const queueStatusDiv = document.getElementById('mail-queue-status');
    
    // 服务器状态
    const runningStatus = status.running ? 
        '<span class="badge bg-success"><i class="fas fa-check"></i> 运行中</span>' :
        '<span class="badge bg-danger"><i class="fas fa-times"></i> 未运行</span>';
    
    const tlsStatus = status.tls_enabled ?
        '<span class="badge bg-info"><i class="fas fa-lock"></i> 已启用</span>' :
        '<span class="badge bg-warning"><i class="fas fa-unlock"></i> 未启用</span>';
    
    serverStatusDiv.innerHTML = `
        <div class="row">
            <div class="col-6">
                <strong>运行状态:</strong><br>
                ${runningStatus}
            </div>
            <div class="col-6">
                <strong>TLS:</strong><br>
                ${tlsStatus}
            </div>
        </div>
        <hr>
        <div class="row">
            <div class="col-6">
                <strong>域名:</strong><br>
                <code>${status.domain}</code>
            </div>
            <div class="col-6">
                <strong>端口:</strong><br>
                SMTP: <code>${status.smtp_port}</code><br>
                IMAP: <code>${status.imap_port}</code>
            </div>
        </div>
    `;
    
    // 队列状态
    if (status.queue_stats) {
        queueStatusDiv.innerHTML = `
            <div class="row text-center">
                <div class="col-6">
                    <h4 class="text-primary">${status.queue_stats.outbound_queue}</h4>
                    <small class="text-muted">出站队列</small>
                </div>
                <div class="col-6">
                    <h4 class="text-warning">${status.queue_stats.retry_queue}</h4>
                    <small class="text-muted">重试队列</small>
                </div>
            </div>
            <hr>
            <div class="text-center">
                <strong>队列处理:</strong>
                ${status.queue_stats.running ? 
                    '<span class="badge bg-success">运行中</span>' : 
                    '<span class="badge bg-danger">已停止</span>'}
            </div>
        `;
    } else {
        queueStatusDiv.innerHTML = '<div class="text-center text-muted">队列信息不可用</div>';
    }
}

// 显示邮件详情模态框
function showMailDetailModal(mail) {
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">邮件详情</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="row mb-3">
                        <div class="col-3"><strong>发件人:</strong></div>
                        <div class="col-9">${mail.from}</div>
                    </div>
                    <div class="row mb-3">
                        <div class="col-3"><strong>收件人:</strong></div>
                        <div class="col-9">${mail.to.join(', ')}</div>
                    </div>
                    <div class="row mb-3">
                        <div class="col-3"><strong>主题:</strong></div>
                        <div class="col-9">${mail.subject}</div>
                    </div>
                    <div class="row mb-3">
                        <div class="col-3"><strong>时间:</strong></div>
                        <div class="col-9">${new Date(mail.timestamp).toLocaleString('zh-CN')}</div>
                    </div>
                    <div class="row mb-3">
                        <div class="col-3"><strong>状态:</strong></div>
                        <div class="col-9">${getStatusBadge(mail.status)}</div>
                    </div>
                    <hr>
                    <h6>邮件内容:</h6>
                    <div class="border p-3" style="max-height: 300px; overflow-y: auto; white-space: pre-wrap; font-family: monospace; font-size: 0.9rem;">
${mail.body || '(无内容)'}
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-success" onclick="downloadEML('${mail.id}')">
                        <i class="fas fa-download"></i> 下载EML
                    </button>
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">关闭</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();
    
    // 模态框关闭后清理
    modal.addEventListener('hidden.bs.modal', () => {
        document.body.removeChild(modal);
    });
}

// 辅助函数：获取状态徽章
function getStatusBadge(status) {
    const badges = {
        'sent': '<span class="badge bg-success">已发送</span>',
        'received': '<span class="badge bg-info">已接收</span>',
        'failed': '<span class="badge bg-danger">失败</span>',
        'queued': '<span class="badge bg-warning">队列中</span>',
        'processing': '<span class="badge bg-primary">处理中</span>'
    };
    return badges[status] || `<span class="badge bg-secondary">${status}</span>`;
}

// 辅助函数：获取方向徽章
function getDirectionBadge(direction) {
    const badges = {
        'inbound': '<span class="badge bg-success"><i class="fas fa-arrow-down"></i> 入站</span>',
        'outbound': '<span class="badge bg-primary"><i class="fas fa-arrow-up"></i> 出站</span>',
        'internal': '<span class="badge bg-info"><i class="fas fa-arrow-right"></i> 内部</span>'
    };
    return badges[direction] || `<span class="badge bg-secondary">${direction}</span>`;
}

// 辅助函数：截断字符串
function truncateString(str, maxLength) {
    if (!str) return '';
    return str.length > maxLength ? str.substring(0, maxLength) + '...' : str;
}

// 辅助函数：格式化字节大小
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 初始化邮件管理功能
function initMailManagement() {
    // 绑定发送邮件表单事件
    const sendMailForm = document.getElementById('send-mail-form');
    if (sendMailForm) {
        sendMailForm.addEventListener('submit', sendMail);
    }
    
    // 当邮件tab被激活时，刷新数据
    const mailTabs = document.querySelectorAll('#mailTabs a');
    mailTabs.forEach(tab => {
        tab.addEventListener('shown.bs.tab', function(e) {
            const target = e.target.getAttribute('href');
            if (target === '#mail-history') {
                refreshMailHistory();
            } else if (target === '#mail-status') {
                getMailServerStatus();
            }
        });
    });
    
    // 当邮件section被激活时，刷新邮件历史
    const mailNavLink = document.querySelector('a[data-section="mail"]');
    if (mailNavLink) {
        mailNavLink.addEventListener('click', function() {
            setTimeout(() => {
                refreshMailHistory();
            }, 100);
        });
    }
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', initMailManagement);