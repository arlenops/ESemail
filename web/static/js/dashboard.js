let currentSection = 'dashboard';
let healthData = null;
let unlockStatus = {}; // 缓存解锁状态

document.addEventListener('DOMContentLoaded', function() {
    // 检查认证状态
    if (!checkAuthToken()) {
        return;
    }

    initializeEventListeners();
    checkSystemStatus();
    // 初始检查解锁状态
    checkUnlockStatus();
    // 定期刷新
    setInterval(refreshDashboard, 30000);
    // 定期检查解锁状态
    setInterval(checkUnlockStatus, 10000);
});

// 检查认证令牌
function checkAuthToken() {
    const token = localStorage.getItem('auth_token');
    if (!token) {
        console.log('没有认证令牌，跳转到登录页面');
        window.location.href = '/login';
        return false;
    }
    return true;
}

function initializeEventListeners() {
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const section = this.getAttribute('href').replace('#', '');
            switchSection(section);
        });
    });

    document.getElementById('init-system-btn').addEventListener('click', initializeSystem);
    document.getElementById('add-domain-form').addEventListener('submit', addDomain);
    document.getElementById('add-user-form').addEventListener('submit', addUser);
    document.getElementById('issue-cert-form').addEventListener('submit', issueCertificate);
}

function switchSection(section) {
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    
    document.querySelector(`[href="#${section}"]`).classList.add('active');

    document.querySelectorAll('[id$="-content"]').forEach(content => {
        content.classList.add('d-none');
    });

    document.getElementById(`${section}-content`).classList.remove('d-none');
    currentSection = section;

    switch(section) {
        case 'dashboard':
            refreshDashboard();
            break;
        case 'domains':
            loadDomains();
            break;
        case 'users':
            loadUsers();
            loadDomainsForUserForm();
            break;
        case 'mail':
            loadMailHistory();
            break;
        case 'certificates':
            loadCertificates();
            break;
        case 'system':
            loadSystemSettings();
            break;
    }
}

async function checkSystemStatus() {
    try {
        const response = await fetch('/api/v1/setup/status');
        const status = await response.json();
        
        if (!status.is_setup) {
            window.location.href = '/';
            return;
        }
        
        // 检查系统初始化状态
        const initResponse = await fetch('/api/v1/system/init-status');
        const initStatus = await initResponse.json();
        
        if (!initStatus.is_initialized) {
            showInitializationModal();
        }
    } catch (error) {
        console.error('检查系统状态失败:', error);
    }
}

function showInitializationModal() {
    const modal = new bootstrap.Modal(document.getElementById('system-init-modal'));
    modal.show();
}

// 检查功能解锁状态
async function checkUnlockStatus() {
    try {
        const response = await fetch('/api/v1/workflow/unlock-status');
        const data = await response.json();

        if (data.success) {
            const newUnlockStatus = data.unlock_status;
            // 检查状态是否有变化
            if (JSON.stringify(newUnlockStatus) !== JSON.stringify(unlockStatus)) {
                unlockStatus = newUnlockStatus;
                updateNavigationUI();
                console.log('功能解锁状态已更新:', unlockStatus);
            }
        }
    } catch (error) {
        console.error('检查解锁状态失败:', error);
    }
}

// 更新导航UI
function updateNavigationUI() {
    const navLinks = document.querySelectorAll('.sidebar .nav-link');

    navLinks.forEach(link => {
        const section = link.getAttribute('data-section');

        // 移除现有状态
        link.classList.remove('disabled');
        link.style.pointerEvents = '';
        link.style.opacity = '';

        // 移除旧的点击事件
        const newLink = link.cloneNode(true);
        link.parentNode.replaceChild(newLink, link);

        // 根据解锁状态更新
        switch(section) {
            case 'domains':
                if (!unlockStatus.domain_config) {
                    newLink.classList.add('disabled');
                    newLink.href = 'javascript:void(0)';
                    newLink.onclick = () => showLockMessage('域名管理', '系统初始化');
                } else {
                    newLink.href = '#domains';
                    newLink.onclick = (e) => { e.preventDefault(); switchSection('domains'); };
                }
                break;

            case 'certificates':
                if (!unlockStatus.ssl_config) {
                    newLink.classList.add('disabled');
                    newLink.href = 'javascript:void(0)';
                    newLink.onclick = () => showLockMessage('证书管理', '域名配置');
                } else {
                    newLink.href = '#certificates';
                    newLink.onclick = (e) => { e.preventDefault(); switchSection('certificates'); };
                }
                break;

            case 'users':
                if (!unlockStatus.user_mgmt) {
                    newLink.classList.add('disabled');
                    newLink.href = 'javascript:void(0)';
                    newLink.onclick = () => showLockMessage('用户管理', '域名配置');
                } else {
                    newLink.href = '#users';
                    newLink.onclick = (e) => { e.preventDefault(); switchSection('users'); };
                }
                break;

            case 'mail':
                if (!unlockStatus.mail_service) {
                    newLink.classList.add('disabled');
                    newLink.href = 'javascript:void(0)';
                    newLink.onclick = () => showLockMessage('邮件服务', '用户管理和SSL证书配置');
                } else {
                    newLink.href = '#mail';
                    newLink.onclick = (e) => { e.preventDefault(); switchSection('mail'); };
                }
                break;

            default:
                // 其他链接保持原有行为
                if (newLink.getAttribute('href').startsWith('#')) {
                    newLink.onclick = (e) => { e.preventDefault(); switchSection(section); };
                }
        }
    });
}

// 显示功能锁定提示
function showLockMessage(feature, requiredStep) {
    // 创建现代化的提示模态框，而不是使用alert
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header bg-warning text-white">
                    <h5 class="modal-title">
                        <i class="fas fa-lock me-2"></i>功能未解锁
                    </h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body text-center">
                    <i class="fas fa-exclamation-triangle text-warning fa-3x mb-3"></i>
                    <h5>${feature} 功能尚未解锁</h5>
                    <p class="text-muted">请先完成：<strong>${requiredStep}</strong></p>
                    <a href="/workflow" class="btn btn-primary mt-2">
                        <i class="fas fa-arrow-right me-2"></i>前往工作流向导
                    </a>
                </div>
            </div>
        </div>
    `;

    document.body.appendChild(modal);
    const bootstrapModal = new bootstrap.Modal(modal);
    bootstrapModal.show();

    // 模态框关闭时清理DOM
    modal.addEventListener('hidden.bs.modal', () => {
        document.body.removeChild(modal);
    });
}

async function initializeSystem() {
    const btn = document.getElementById('init-system-btn');
    const progress = document.getElementById('init-progress');
    const stepsDiv = document.getElementById('init-steps');
    
    btn.disabled = true;
    btn.textContent = '初始化中...';
    progress.classList.remove('d-none');
    
    try {
        const response = await fetch('/api/v1/system/init', { method: 'POST' });
        const result = await response.json();
        
        const progressBar = progress.querySelector('.progress-bar');
        const totalSteps = result.steps.length;
        
        result.steps.forEach((step, index) => {
            const progress = ((index + 1) / totalSteps) * 100;
            progressBar.style.width = progress + '%';
            progressBar.textContent = Math.round(progress) + '%';
            
            const stepDiv = document.createElement('div');
            stepDiv.className = `alert ${step.status === 'completed' ? 'alert-success' : step.status === 'failed' ? 'alert-danger' : 'alert-info'}`;
            stepDiv.textContent = `${step.description}: ${step.status === 'completed' ? '完成' : step.status === 'failed' ? '失败 - ' + step.error : '进行中'}`;
            stepsDiv.appendChild(stepDiv);
        });
        
        if (result.success) {
            // 系统初始化成功后立即检查解锁状态
            setTimeout(async () => {
                await checkUnlockStatus();
                location.reload();
            }, 2000);
        } else {
            btn.disabled = false;
            btn.textContent = '重试初始化';
        }
    } catch (error) {
        console.error('初始化失败:', error);
        btn.disabled = false;
        btn.textContent = '重试初始化';
    }
}

async function refreshDashboard() {
    if (currentSection !== 'dashboard') return;
    
    try {
        const response = await fetch('/api/v1/health');
        healthData = await response.json();
        
        updateOverallStatus();
        updateServicesTable();
        updateSystemResources();
        updateStatistics();
    } catch (error) {
        console.error('获取健康状态失败:', error);
    }
}

function updateOverallStatus() {
    const statusElement = document.getElementById('overall-status');
    const parentCard = statusElement.closest('.card');
    
    parentCard.className = 'card text-white';
    
    switch(healthData.overall_state) {
        case 'healthy':
            parentCard.classList.add('bg-success');
            statusElement.textContent = '运行正常';
            break;
        case 'warning':
            parentCard.classList.add('bg-warning');
            statusElement.textContent = '有警告';
            break;
        case 'critical':
            parentCard.classList.add('bg-danger');
            statusElement.textContent = '有故障';
            break;
        default:
            parentCard.classList.add('bg-secondary');
            statusElement.textContent = '未知状态';
    }
}

function updateServicesTable() {
    const tbody = document.getElementById('services-table');
    tbody.innerHTML = '';
    
    healthData.services.forEach(service => {
        const row = document.createElement('tr');
        
        const statusBadge = getStatusBadge(service.status);
        const port = service.port ? service.port : '-';
        const processId = service.process_id || '-';
        const lastCheck = new Date(service.last_check).toLocaleTimeString();
        
        row.innerHTML = `
            <td>${service.name}</td>
            <td>${statusBadge}</td>
            <td>${port}</td>
            <td>${processId}</td>
            <td>${lastCheck}</td>
            <td>${service.message}</td>
        `;
        
        tbody.appendChild(row);
    });
}

function updateSystemResources() {
    const cpuProgress = document.getElementById('cpu-progress');
    const memoryProgress = document.getElementById('memory-progress');
    const diskProgress = document.getElementById('disk-progress');
    
    const cpu = healthData.system_info.cpu_usage || 0;
    const memory = healthData.system_info.memory_usage || 0;
    const disk = healthData.system_info.disk_usage || 0;
    
    cpuProgress.style.width = cpu + '%';
    cpuProgress.textContent = cpu.toFixed(1) + '%';
    
    memoryProgress.style.width = memory + '%';
    memoryProgress.textContent = memory.toFixed(1) + '%';
    
    diskProgress.style.width = disk + '%';
    diskProgress.textContent = disk.toFixed(1) + '%';
    
    document.getElementById('system-uptime').textContent = healthData.system_info.uptime || '-';
    document.getElementById('load-average').textContent = healthData.system_info.load_average || '-';
    
    document.getElementById('disk-usage').textContent = disk.toFixed(1) + '%';
}

function updateStatistics() {
    document.getElementById('today-mails').textContent = '0';
    document.getElementById('user-count').textContent = '0';
}

function getStatusBadge(status) {
    const badges = {
        'healthy': '<span class="badge bg-success">正常</span>',
        'warning': '<span class="badge bg-warning">警告</span>',
        'critical': '<span class="badge bg-danger">故障</span>',
        'unknown': '<span class="badge bg-secondary">未知</span>'
    };
    return badges[status] || badges['unknown'];
}

// 加载域名到用户表单
async function loadDomainsForUserForm() {
    try {
        const response = await fetch('/api/v1/domains', {
            headers: getAuthHeaders()
        });
        const domains = await response.json();
        
        const domainSelect = document.getElementById('user-domain');
        if (domainSelect) {
            domainSelect.innerHTML = '<option value="">选择域名</option>';
            domains.forEach(domain => {
                domainSelect.innerHTML += `<option value="${domain.domain}">${domain.domain}</option>`;
            });
        }
    } catch (error) {
        console.error('加载域名失败:', error);
    }
}

async function loadDomains() {
    try {
        const response = await fetch('/api/v1/domains', {
            headers: getAuthHeaders()
        });
        const domains = await response.json();
        
        let html = '<div class="row">';
        domains.forEach(domain => {
            html += `
                <div class="col-md-6 mb-3">
                    <div class="card">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h5>${domain.name}</h5>
                            <span class="badge ${domain.active ? 'bg-success' : 'bg-secondary'}">${domain.active ? '活跃' : '禁用'}</span>
                        </div>
                        <div class="card-body">
                            <button class="btn btn-sm btn-outline-primary" onclick="viewDNSRecords('${domain.name}')">查看DNS记录</button>
                            <button class="btn btn-sm btn-outline-danger" onclick="deleteDomain('${domain.name}')">删除域名</button>
                        </div>
                    </div>
                </div>
            `;
        });
        html += '</div>';
        
        document.getElementById('domains-list').innerHTML = html;
    } catch (error) {
        console.error('加载域名失败:', error);
    }
}

async function loadUsers() {
    try {
        const response = await fetch('/api/v1/users', {
            headers: getAuthHeaders()
        });
        const users = await response.json();
        
        let html = `
            <div class="table-responsive">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>邮箱地址</th>
                            <th>姓名</th>
                            <th>域名</th>
                            <th>状态</th>
                            <th>配额使用</th>
                            <th>创建时间</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
        `;
        
        users.forEach(user => {
            const quotaPercent = (user.used_quota / user.quota * 100).toFixed(1);
            html += `
                <tr>
                    <td>${user.email}</td>
                    <td>${user.name}</td>
                    <td>${user.domain}</td>
                    <td><span class="badge ${user.active ? 'bg-success' : 'bg-secondary'}">${user.active ? '活跃' : '禁用'}</span></td>
                    <td>
                        <div class="progress" style="width: 100px;">
                            <div class="progress-bar" style="width: ${quotaPercent}%"></div>
                        </div>
                        <small>${quotaPercent}%</small>
                    </td>
                    <td>${new Date(user.created_at).toLocaleDateString()}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary" onclick="resetUserPassword('${user.id}')">重置密码</button>
                        <button class="btn btn-sm btn-outline-danger" onclick="deleteUser('${user.id}')">删除</button>
                    </td>
                </tr>
            `;
        });
        
        html += `
                    </tbody>
                </table>
            </div>
        `;
        
        document.getElementById('users-list').innerHTML = html;
    } catch (error) {
        console.error('加载用户失败:', error);
    }
}

async function loadMailHistory() {
    try {
        const response = await fetch('/api/v1/mail/history?page=1&page_size=50');
        const result = await response.json();
        
        let html = `
            <div class="table-responsive">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>时间</th>
                            <th>方向</th>
                            <th>发件人</th>
                            <th>收件人</th>
                            <th>主题</th>
                            <th>状态</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
        `;
        
        result.records.forEach(record => {
            html += `
                <tr>
                    <td>${new Date(record.timestamp).toLocaleString()}</td>
                    <td><span class="badge ${record.direction === 'inbound' ? 'bg-success' : 'bg-primary'}">${record.direction === 'inbound' ? '入站' : '出站'}</span></td>
                    <td>${record.from}</td>
                    <td>${record.to.join(', ')}</td>
                    <td>${record.subject || '-'}</td>
                    <td><span class="badge bg-info">${record.status}</span></td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary" onclick="viewMailDetail('${record.id}')">详情</button>
                        <button class="btn btn-sm btn-outline-secondary" onclick="downloadEML('${record.id}')">下载</button>
                    </td>
                </tr>
            `;
        });
        
        html += `
                    </tbody>
                </table>
            </div>
            <nav>
                <ul class="pagination justify-content-center">
                    <li class="page-item"><a class="page-link" href="#" onclick="loadMailHistoryPage(${result.page - 1})">上一页</a></li>
                    <li class="page-item active"><a class="page-link" href="#">第 ${result.page} 页 / 共 ${result.total_pages} 页</a></li>
                    <li class="page-item"><a class="page-link" href="#" onclick="loadMailHistoryPage(${result.page + 1})">下一页</a></li>
                </ul>
            </nav>
        `;
        
        document.getElementById('mail-history').innerHTML = html;
    } catch (error) {
        console.error('加载邮件历史失败:', error);
    }
}

async function loadCertificates() {
    try {
        const response = await fetch('/api/v1/certificates', {
            headers: getAuthHeaders()
        });
        const certificates = await response.json();
        
        let html = `
            <div class="table-responsive">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>域名</th>
                            <th>类型</th>
                            <th>状态</th>
                            <th>签发时间</th>
                            <th>过期时间</th>
                            <th>颁发者</th>
                            <th>自动续签</th>
                        </tr>
                    </thead>
                    <tbody>
        `;
        
        certificates.forEach(cert => {
            const statusBadge = cert.status === 'valid' ? 'bg-success' : 
                               cert.status === 'expiring' ? 'bg-warning' : 'bg-danger';
            html += `
                <tr>
                    <td>${cert.domain}</td>
                    <td>${cert.type === 'wildcard' ? '通配符' : '单域名'}</td>
                    <td><span class="badge ${statusBadge}">${cert.status}</span></td>
                    <td>${new Date(cert.issued_at).toLocaleDateString()}</td>
                    <td>${new Date(cert.expires_at).toLocaleDateString()}</td>
                    <td>${cert.issuer}</td>
                    <td>${cert.auto_renew ? '✓' : '✗'}</td>
                </tr>
            `;
        });
        
        html += `
                    </tbody>
                </table>
            </div>
        `;
        
        document.getElementById('certificates-list').innerHTML = html;
    } catch (error) {
        console.error('加载证书失败:', error);
    }
}

async function loadSystemSettings() {
    try {
        const response = await fetch('/api/v1/system/status');
        const status = await response.json();
        
        let html = `
            <table class="table">
                <tr><td>系统版本</td><td>${status.version}</td></tr>
                <tr><td>安装路径</td><td>${status.install_path}</td></tr>
                <tr><td>配置路径</td><td>${status.config_path}</td></tr>
                <tr><td>系统状态</td><td>${status.initialized ? '已初始化' : '未初始化'}</td></tr>
            </table>
            
            <h6>服务状态</h6>
            <table class="table">
        `;
        
        for (const [service, status] of Object.entries(status.services_status)) {
            html += `<tr><td>${service}</td><td><span class="badge ${status === 'active' ? 'bg-success' : 'bg-danger'}">${status}</span></td></tr>`;
        }
        
        html += `</table>`;
        
        document.getElementById('system-info').innerHTML = html;
    } catch (error) {
        console.error('加载系统设置失败:', error);
    }
}

// 获取认证头
function getAuthHeaders() {
    const token = localStorage.getItem('auth_token');
    const csrfToken = getCSRFToken();
    
    const headers = {
        'Content-Type': 'application/json'
    };
    
    if (token) {
        headers['Authorization'] = 'Bearer ' + token;
    }
    
    if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
    }
    
    return headers;
}

// 获取CSRF令牌
function getCSRFToken() {
    // 从cookie获取
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'csrf-token') {
            return decodeURIComponent(value);
        }
    }
    
    // 从meta标签获取
    const metaToken = document.querySelector('meta[name="csrf-token"]');
    if (metaToken) {
        return metaToken.getAttribute('content');
    }
    
    return null;
}

async function addDomain(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData.entries());
    
    // 确保data只包含domain字段，符合后端API的期望
    const requestData = {
        domain: data.domain
    };
    
    const headers = getAuthHeaders();
    console.log('发送域名添加请求，数据:', requestData);
    console.log('发送域名添加请求，headers:', headers);
    console.log('CSRF令牌:', getCSRFToken());
    
    try {
        const response = await fetch('/api/v1/domains', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify(requestData)
        });
        
        if (response.ok) {
            bootstrap.Modal.getInstance(document.getElementById('add-domain-modal')).hide();
            // 清空表单
            document.getElementById('add-domain-form').reset();
            // 立即检查解锁状态
            await checkUnlockStatus();
            // 重新加载域名列表
            loadDomains();
            // 显示DNS设置引导
            setTimeout(() => {
                showDNSSetupGuide(requestData.domain);
            }, 500);
        } else {
            const error = await response.json();
            alert('添加失败: ' + error.error);
            console.error('添加域名失败:', error);
        }
    } catch (error) {
        alert('添加失败: ' + error.message);
        console.error('添加域名错误:', error);
    }
}

async function addUser(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData.entries());
    
    // 组合完整的邮箱地址
    if (data.email_local && data.domain) {
        data.email = data.email_local + '@' + data.domain;
        delete data.email_local;
    } else {
        alert('请选择域名和填写用户名');
        return;
    }
    
    data.quota = parseInt(data.quota) * 1024 * 1024;
    
    // 禁用提交按钮防止重复提交
    const submitButton = e.target.querySelector('button[type="submit"]');
    const originalText = submitButton.textContent;
    submitButton.disabled = true;
    submitButton.textContent = '创建中...';
    
    try {
        const response = await fetch('/api/v1/users', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify(data)
        });
        
        const result = await response.json();
        
        if (response.ok) {
            alert('用户创建成功');
            bootstrap.Modal.getInstance(document.getElementById('add-user-modal')).hide();
            // 重置表单  
            document.getElementById('add-user-form').reset();
            // 刷新用户列表
            loadUsers();
            // 同时刷新邮件发送页面的邮箱选项
            loadUserEmailOptions();
        } else {
            // 显示服务器返回的错误信息
            alert('创建失败: ' + (result.error || '未知错误'));
        }
    } catch (error) {
        console.error('创建用户请求失败:', error);
        alert('创建失败: 网络错误或服务器无响应');
    } finally {
        // 恢复提交按钮状态
        submitButton.disabled = false;
        submitButton.textContent = originalText;
    }
}

async function issueCertificate(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData.entries());
    
    // 根据证书类型调整域名
    if (data.cert_type === 'mail') {
        data.domain = 'mail.' + data.domain;
    } else if (data.cert_type === 'wildcard') {
        data.domain = '*.' + data.domain;
        data.validation_method = 'dns'; // 通配符证书强制使用DNS验证
    }
    
    const submitBtn = document.getElementById('issue-cert-submit');
    const originalText = submitBtn.innerHTML;
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>处理中...';
    
    try {
        const response = await fetch('/api/v1/certificates/issue', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify(data)
        });
        
        const result = await response.json();
        
        if (response.ok) {
            if (data.validation_method === 'dns') {
                // 显示DNS验证信息
                showDNSValidation(result.dns_name, result.dns_value);
            } else {
                // HTTP验证直接完成
                alert('证书申请成功');
                bootstrap.Modal.getInstance(document.getElementById('issue-cert-modal')).hide();
                loadCertificates();
            }
        } else {
            alert('申请失败: ' + result.error);
        }
    } catch (error) {
        console.error('申请证书失败:', error);
        alert('网络错误，请重试');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalText;
    }
}

// 显示DNS验证信息
function showDNSValidation(dnsName, dnsValue) {
    // 隐藏表单，显示DNS验证区域
    document.getElementById('issue-cert-form').style.display = 'none';
    document.getElementById('dns-validation-section').classList.remove('d-none');
    
    // 填充DNS记录信息
    document.getElementById('dns-record-name').value = dnsName;
    document.getElementById('dns-record-value').value = dnsValue;
    
    // 切换按钮显示
    document.getElementById('issue-cert-submit').classList.add('d-none');
    document.getElementById('continue-validation-btn').classList.remove('d-none');
    document.getElementById('back-to-form-btn').classList.remove('d-none');
}

// 复制到剪贴板功能
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    element.select();
    element.setSelectionRange(0, 99999); // 兼容移动设备
    
    try {
        document.execCommand('copy');
        // 显示复制成功提示
        const button = element.nextElementSibling;
        const originalIcon = button.innerHTML;
        button.innerHTML = '<i class="fas fa-check text-success"></i>';
        setTimeout(() => {
            button.innerHTML = originalIcon;
        }, 2000);
    } catch (err) {
        console.error('复制失败:', err);
        alert('复制失败，请手动选择并复制');
    }
}

// 继续验证DNS记录
async function continueValidation() {
    const continueBtn = document.getElementById('continue-validation-btn');
    const originalText = continueBtn.innerHTML;
    continueBtn.disabled = true;
    continueBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>验证中...';
    
    const resultDiv = document.getElementById('dns-validation-result');
    
    try {
        const response = await fetch('/api/v1/certificates/validate-dns', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({
                dns_name: document.getElementById('dns-record-name').value,
                dns_value: document.getElementById('dns-record-value').value
            })
        });
        
        const result = await response.json();
        
        if (response.ok && result.success) {
            resultDiv.innerHTML = `
                <div class="alert alert-success">
                    <i class="fas fa-check-circle me-2"></i>
                    <strong>DNS验证成功！</strong><br>
                    <small>证书正在申请中，请稍候...</small>
                </div>
            `;
            
            // 等待证书签发完成
            setTimeout(() => {
                bootstrap.Modal.getInstance(document.getElementById('issue-cert-modal')).hide();
                loadCertificates();
                alert('证书申请成功！');
            }, 3000);
        } else {
            resultDiv.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    <strong>DNS验证失败</strong><br>
                    <small>${result.error || 'DNS记录未找到或未生效，请检查DNS设置'}</small>
                </div>
            `;
        }
    } catch (error) {
        console.error('DNS验证失败:', error);
        resultDiv.innerHTML = `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <strong>验证请求失败</strong><br>
                <small>网络错误，请检查连接后重试</small>
            </div>
        `;
    } finally {
        continueBtn.disabled = false;
        continueBtn.innerHTML = originalText;
    }
}

// 返回表单
function backToForm() {
    // 显示表单，隐藏DNS验证区域
    document.getElementById('issue-cert-form').style.display = 'block';
    document.getElementById('dns-validation-section').classList.add('d-none');
    
    // 切换按钮显示
    document.getElementById('issue-cert-submit').classList.remove('d-none');
    document.getElementById('continue-validation-btn').classList.add('d-none');
    document.getElementById('back-to-form-btn').classList.add('d-none');
    
    // 清空结果显示
    document.getElementById('dns-validation-result').innerHTML = '';
}

async function renewCertificates() {
    try {
        const response = await fetch('/api/v1/certificates/renew', { 
            method: 'POST',
            headers: getAuthHeaders()
        });
        if (response.ok) {
            alert('证书续签成功');
            loadCertificates();
        } else {
            const error = await response.json();
            alert('续签失败: ' + error.error);
        }
    } catch (error) {
        alert('续签失败: ' + error.message);
    }
}

async function downloadEML(id) {
    window.open(`/api/v1/mail/history/${id}/download`, '_blank');
}

// DNS设置引导
async function showDNSSetupGuide(domain) {
    try {
        // 获取DNS记录建议
        const response = await fetch(`/api/v1/domains/${domain}/dns`);
        const records = await response.json();
        
        let html = `
            <div class="modal fade" id="dns-setup-guide-modal" tabindex="-1">
                <div class="modal-dialog modal-xl">
                    <div class="modal-content">
                        <div class="modal-header bg-success text-white">
                            <h5 class="modal-title">
                                <i class="fas fa-check-circle"></i> 域名添加成功！请配置DNS记录
                            </h5>
                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <div class="alert alert-success">
                                <h6><i class="fas fa-checkmark-circle"></i> 域名 ${domain} 已成功添加到邮件系统！</h6>
                                <p class="mb-0">现在您需要在DNS服务商处配置以下记录以启用邮件服务。</p>
                            </div>
                            
                            <div class="row mb-4">
                                <div class="col-md-8">
                                    <h6><i class="fas fa-cog"></i> DNS记录配置表</h6>
                                    <div class="table-responsive">
                                        <table class="table table-bordered table-striped">
                                            <thead class="table-dark">
                                                <tr>
                                                    <th>记录类型</th>
                                                    <th>主机记录</th>
                                                    <th>记录值</th>
                                                    <th>TTL</th>
                                                    <th>优先级</th>
                                                </tr>
                                            </thead>
                                            <tbody>
        `;
        
        records.forEach(record => {
            const priority = record.type === 'MX' ? '10' : '-';
            html += `
                <tr>
                    <td><code class="text-primary">${record.type}</code></td>
                    <td><code>${record.name}</code></td>
                    <td><code class="text-break">${record.value}</code></td>
                    <td>${record.ttl || 600}</td>
                    <td>${priority}</td>
                </tr>
            `;
        });
        
        html += `
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                                <div class="col-md-4">
                                    <h6><i class="fas fa-lightbulb"></i> 配置说明</h6>
                                    <div class="card">
                                        <div class="card-body">
                                            <ul class="list-unstyled">
                                                <li class="mb-2">
                                                    <strong>MX记录：</strong><br>
                                                    <small class="text-muted">指向邮件服务器，用于接收邮件</small>
                                                </li>
                                                <li class="mb-2">
                                                    <strong>A记录：</strong><br>
                                                    <small class="text-muted">邮件服务器的IP地址</small>
                                                </li>
                                                <li class="mb-2">
                                                    <strong>TXT记录：</strong><br>
                                                    <small class="text-muted">SPF/DKIM/DMARC验证记录</small>
                                                </li>
                                            </ul>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="alert alert-info">
                                <h6><i class="fas fa-info-circle"></i> 重要提示</h6>
                                <ul class="mb-0">
                                    <li>DNS记录生效通常需要几分钟到24小时</li>
                                    <li>配置完成后，请使用"DNS记录"按钮检查配置状态</li>
                                    <li>所有记录配置正确后，邮件服务才能正常工作</li>
                                    <li>如需帮助，请查看DNS服务商的配置文档</li>
                                </ul>
                            </div>
                            
                            <div class="alert alert-warning">
                                <h6><i class="fas fa-exclamation-triangle"></i> 常见DNS服务商配置指南</h6>
                                <div class="row">
                                    <div class="col-md-4">
                                        <strong>阿里云DNS：</strong><br>
                                        <small>进入域名控制台 → DNS管理 → 添加记录</small>
                                    </div>
                                    <div class="col-md-4">
                                        <strong>腾讯云DNS：</strong><br>
                                        <small>进入DNS解析控制台 → 记录管理 → 添加记录</small>
                                    </div>
                                    <div class="col-md-4">
                                        <strong>Cloudflare：</strong><br>
                                        <small>进入Dashboard → DNS → Add record</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                                <i class="fas fa-times"></i> 稍后配置
                            </button>
                            <button type="button" class="btn btn-primary" onclick="viewDNSRecords('${domain}')">
                                <i class="fas fa-eye"></i> 检查DNS状态
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // 移除旧的模态框
        const oldModal = document.getElementById('dns-setup-guide-modal');
        if (oldModal) {
            oldModal.remove();
        }
        
        // 添加新的模态框
        document.body.insertAdjacentHTML('beforeend', html);
        
        // 显示模态框
        const modal = new bootstrap.Modal(document.getElementById('dns-setup-guide-modal'));
        modal.show();
        
    } catch (error) {
        console.error('获取DNS设置引导失败:', error);
        // 如果获取失败，至少显示一个成功提示
        alert(`域名 ${domain} 添加成功！请在域名管理页面查看DNS配置要求。`);
    }
}