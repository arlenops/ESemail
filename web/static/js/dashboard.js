let currentSection = 'dashboard';
let healthData = null;

document.addEventListener('DOMContentLoaded', function() {
    initializeEventListeners();
    checkSystemStatus();
    setInterval(refreshDashboard, 30000);
});

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
        
        const systemResponse = await fetch('/api/v1/system/status');
        const systemStatus = await systemResponse.json();
        
        if (!systemStatus.initialized) {
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
            setTimeout(() => {
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

async function loadDomains() {
    try {
        const response = await fetch('/api/v1/domains');
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
        const response = await fetch('/api/v1/users');
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
        const response = await fetch('/api/v1/certificates');
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

async function addDomain(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData.entries());
    
    try {
        const response = await fetch('/api/v1/domains', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        
        if (response.ok) {
            alert('域名添加成功');
            bootstrap.Modal.getInstance(document.getElementById('add-domain-modal')).hide();
            loadDomains();
        } else {
            const error = await response.json();
            alert('添加失败: ' + error.error);
        }
    } catch (error) {
        alert('添加失败: ' + error.message);
    }
}

async function addUser(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData.entries());
    data.quota = parseInt(data.quota) * 1024 * 1024;
    
    try {
        const response = await fetch('/api/v1/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        
        if (response.ok) {
            alert('用户创建成功');
            bootstrap.Modal.getInstance(document.getElementById('add-user-modal')).hide();
            loadUsers();
        } else {
            const error = await response.json();
            alert('创建失败: ' + error.error);
        }
    } catch (error) {
        alert('创建失败: ' + error.message);
    }
}

async function issueCertificate(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData.entries());
    
    try {
        const response = await fetch('/api/v1/certificates/issue', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        
        if (response.ok) {
            alert('证书签发成功');
            bootstrap.Modal.getInstance(document.getElementById('issue-cert-modal')).hide();
            loadCertificates();
        } else {
            const error = await response.json();
            alert('签发失败: ' + error.error);
        }
    } catch (error) {
        alert('签发失败: ' + error.message);
    }
}

async function renewCertificates() {
    try {
        const response = await fetch('/api/v1/certificates/renew', { method: 'POST' });
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