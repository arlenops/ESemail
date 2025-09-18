let currentSection = 'dashboard';
let healthData = null;

// 通用模态框函数
function showModal(title, message, type = 'info', actions = []) {
    // 移除已存在的模态框
    const existingModal = document.getElementById('universal-modal');
    if (existingModal) {
        existingModal.remove();
    }

    const typeConfig = {
        'success': { icon: 'fas fa-check-circle', headerClass: 'bg-success', iconClass: 'text-success' },
        'error': { icon: 'fas fa-exclamation-triangle', headerClass: 'bg-danger', iconClass: 'text-danger' },
        'warning': { icon: 'fas fa-exclamation-triangle', headerClass: 'bg-warning', iconClass: 'text-warning' },
        'info': { icon: 'fas fa-info-circle', headerClass: 'bg-primary', iconClass: 'text-primary' }
    };

    const config = typeConfig[type] || typeConfig['info'];

    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.id = 'universal-modal';
    modal.setAttribute('tabindex', '-1');

    let actionsHtml = '';
    if (actions.length > 0) {
        actions.forEach(action => {
            actionsHtml += `<button type="button" class="btn ${action.class || 'btn-primary'}" onclick="${action.onclick || ''}" ${action.dismiss ? 'data-bs-dismiss="modal"' : ''}>${action.text}</button>`;
        });
    } else {
        actionsHtml = '<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">关闭</button>';
    }

    modal.innerHTML = `
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header ${config.headerClass} text-white">
                    <h5 class="modal-title">
                        <i class="${config.icon} me-2"></i>${title}
                    </h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="text-center mb-3">
                        <i class="${config.icon} ${config.iconClass} fa-3x mb-3"></i>
                    </div>
                    <div class="text-center">${message}</div>
                </div>
                <div class="modal-footer">
                    ${actionsHtml}
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

    return bootstrapModal;
}

document.addEventListener('DOMContentLoaded', function() {
    // 检查认证状态
    if (!checkAuthToken()) {
        return;
    }

    initializeEventListeners();
    checkSystemStatus();
    // 定期刷新
    setInterval(refreshDashboard, 30000);
    // 初始化导航系统
    initializeNavigation();
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
    // 不在这里添加导航事件监听器，改为在updateNavigationUI中统一处理

    // 系统初始化按钮已移除
    document.getElementById('add-domain-form').addEventListener('submit', addDomain);
    document.getElementById('add-user-form').addEventListener('submit', addUser);
    document.getElementById('issue-cert-form').addEventListener('submit', issueCertificate);
}

function showSection(section) {
    console.log('Switching to section:', section);

    // 移除所有导航链接的active状态
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });

    // 添加active状态到当前section的导航链接
    const activeLink = document.querySelector(`[data-section="${section}"]`);
    if (activeLink) {
        activeLink.classList.add('active');
    } else {
        console.warn('找不到对应的导航链接:', section);
    }

    // 隐藏所有内容区域 - 使用正确的选择器
    document.querySelectorAll('.section-content').forEach(content => {
        content.style.display = 'none';
    });

    // 显示当前section的内容区域 - 使用正确的ID格式
    const contentElement = document.getElementById(`${section}-section`);
    if (contentElement) {
        contentElement.style.display = 'block';
    } else {
        console.warn('找不到对应的内容区域:', `${section}-section`);
    }

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
        // 简化：直接检查系统状态，不再检查设置状态
        const initResponse = await fetch('/api/v1/system/status');
        if (!initResponse.ok) {
            console.log('系统状态检查失败，可能需要初始化');
            return;
        }

        const initStatus = await initResponse.json();
        console.log('系统状态:', initStatus);

        // 系统已经简化，不需要显示初始化模态框
    } catch (error) {
        console.error('检查系统状态失败:', error);
    }
}

// 系统初始化模态框已移除

// 初始化导航系统
function initializeNavigation() {
    const navLinks = document.querySelectorAll('.sidebar .nav-link');

    navLinks.forEach(link => {
        const section = link.getAttribute('data-section');

        // 移除可能的禁用状态
        link.classList.remove('disabled');
        link.style.pointerEvents = '';
        link.style.opacity = '';

        // 为所有导航项添加点击事件
        link.addEventListener('click', (e) => {
            e.preventDefault();

            // 检查是否需要认证
            if (section !== 'dashboard' && section !== 'system') {
                if (!checkAuthToken()) {
                    return;
                }
            }

            showSection(section);
        });
    });
}

// 系统初始化功能已移除

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
                const domainName = domain.email_domain || domain.domain || domain.name;
                domainSelect.innerHTML += `<option value="${domainName}">${domainName}</option>`;
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
            const domainName = domain.email_domain || domain.domain || domain.name;
            html += `
                <div class="col-md-6 mb-3">
                    <div class="card">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h5>${domainName}</h5>
                            <span class="badge ${domain.active ? 'bg-success' : 'bg-secondary'}">${domain.active ? '活跃' : '禁用'}</span>
                        </div>
                        <div class="card-body">
                            <button class="btn btn-sm btn-outline-primary" onclick="viewDNSRecords('${domainName}')">查看DNS记录</button>
                            <button class="btn btn-sm btn-outline-danger" onclick="deleteDomain('${domainName}')">删除域名</button>
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
            // 重新加载域名列表
            loadDomains();
            // 显示DNS设置引导
            setTimeout(() => {
                showDNSSetupGuide(requestData.domain);
            }, 500);
        } else {
            const error = await response.json();
            showModal('添加失败', error.error || '域名添加失败，请重试', 'error');
            console.error('添加域名失败:', error);
        }
    } catch (error) {
        showModal('添加失败', error.message || '网络错误，请重试', 'error');
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
        showModal('选择错误', '请选择域名和填写用户名', 'warning');
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
            showModal('创建成功', '用户创建成功', 'success');
            bootstrap.Modal.getInstance(document.getElementById('add-user-modal')).hide();
            // 重置表单
            document.getElementById('add-user-form').reset();
            // 刷新用户列表
            loadUsers();
            // 同时刷新邮件发送页面的邮箱选项
            loadUserEmailOptions();
        } else {
            // 显示服务器返回的错误信息
            showModal('创建失败', result.error || '未知错误', 'error');
        }
    } catch (error) {
        console.error('创建用户请求失败:', error);
        showModal('创建失败', '网络错误或服务器无响应', 'error');
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
        // 通配符证书强制使用DNS验证
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
            if (result.dns_name && result.dns_value) {
                // DNS验证流程
                showDNSValidation(result.dns_name, result.dns_value);
            } else if (result.success) {
                // 证书直接申请成功
                showModal('申请成功', result.message || '证书申请成功', 'success');
                bootstrap.Modal.getInstance(document.getElementById('issue-cert-modal')).hide();
                loadCertificates();
            }
        } else {
            showModal('申请失败', result.error || '证书申请失败', 'error');
        }
    } catch (error) {
        console.error('申请证书失败:', error);
        showModal('网络错误', '网络错误，请重试', 'error');
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
        showModal('复制失败', '复制失败，请手动选择并复制', 'warning');
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
        // 获取当前域名
        const domain = getCurrentDomain();
        if (!domain) {
            throw new Error('无法获取域名信息');
        }

        const response = await fetch(`/api/v1/certificates/validate-dns/${domain}`, {
            method: 'POST',
            headers: getAuthHeaders()
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
                showModal('申请成功', '证书申请成功！', 'success');
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

// 获取当前域名（用于验证）
function getCurrentDomain() {
    // 从表单数据中获取域名
    const formData = new FormData(document.getElementById('issue-cert-form'));
    const data = Object.fromEntries(formData.entries());

    let domain = data.domain;

    // 根据证书类型调整域名
    if (data.cert_type === 'mail') {
        domain = 'mail.' + domain;
    } else if (data.cert_type === 'wildcard') {
        domain = '*.' + domain;
    }

    return domain;
}

// 返回表单
function backToForm() {
    // 显示表单，隐藏验证区域
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
            showModal('续签成功', '证书续签成功', 'success');
            loadCertificates();
        } else {
            const error = await response.json();
            showModal('续签失败', error.error || '证书续签失败', 'error');
        }
    } catch (error) {
        showModal('续签失败', error.message || '网络错误', 'error');
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
        showModal('域名添加成功', `域名 ${domain} 添加成功！请在域名管理页面查看DNS配置要求。`, 'success');
    }
}

// 添加缺失的函数
async function viewDNSRecords(domain) {
    try {
        const response = await fetch(`/api/v1/domains/${domain}/dns-check`, {
            headers: getAuthHeaders()
        });
        const result = await response.json();

        if (response.ok) {
            showModal('DNS记录状态', `域名 ${domain} 的DNS记录检查完成`, 'info');
        } else {
            showModal('DNS检查失败', result.error || 'DNS检查失败', 'error');
        }
    } catch (error) {
        console.error('DNS记录查看失败:', error);
        showModal('DNS检查失败', '网络错误，请重试', 'error');
    }
}

async function deleteDomain(domain) {
    if (domain === 'caiji.wiki') {
        showModal('删除失败', '不能删除主域名', 'warning');
        return;
    }

    if (!confirm(`确定要删除域名 ${domain} 吗？此操作不可撤销。`)) {
        return;
    }

    try {
        const response = await fetch(`/api/v1/domains/${domain}`, {
            method: 'DELETE',
            headers: getAuthHeaders()
        });

        if (response.ok) {
            showModal('删除成功', '域名删除成功', 'success');
            loadDomains();
        } else {
            const result = await response.json();
            showModal('删除失败', result.error || '域名删除失败', 'error');
        }
    } catch (error) {
        console.error('删除域名失败:', error);
        showModal('删除失败', '网络错误，请重试', 'error');
    }
}

async function resetUserPassword(userId) {
    if (!confirm('确定要重置该用户的密码吗？')) {
        return;
    }

    try {
        const response = await fetch(`/api/v1/users/${userId}/reset-password`, {
            method: 'POST',
            headers: getAuthHeaders()
        });

        if (response.ok) {
            const result = await response.json();
            showModal('重置成功', `密码重置成功，新密码：${result.new_password}`, 'success');
        } else {
            const result = await response.json();
            showModal('重置失败', result.error || '密码重置失败', 'error');
        }
    } catch (error) {
        console.error('重置密码失败:', error);
        showModal('重置失败', '网络错误，请重试', 'error');
    }
}

async function deleteUser(userId) {
    if (!confirm('确定要删除该用户吗？此操作不可撤销。')) {
        return;
    }

    try {
        const response = await fetch(`/api/v1/users/${userId}`, {
            method: 'DELETE',
            headers: getAuthHeaders()
        });

        if (response.ok) {
            showModal('删除成功', '用户删除成功', 'success');
            loadUsers();
        } else {
            const result = await response.json();
            showModal('删除失败', result.error || '用户删除失败', 'error');
        }
    } catch (error) {
        console.error('删除用户失败:', error);
        showModal('删除失败', '网络错误，请重试', 'error');
    }
}

async function viewMailDetail(mailId) {
    try {
        const response = await fetch(`/api/v1/mail/history/${mailId}`, {
            headers: getAuthHeaders()
        });

        if (response.ok) {
            const mail = await response.json();
            showModal('邮件详情', `
                <div class="text-left">
                    <p><strong>发件人:</strong> ${mail.from}</p>
                    <p><strong>收件人:</strong> ${mail.to.join(', ')}</p>
                    <p><strong>主题:</strong> ${mail.subject}</p>
                    <p><strong>时间:</strong> ${new Date(mail.timestamp).toLocaleString()}</p>
                    <p><strong>状态:</strong> ${mail.status}</p>
                </div>
            `, 'info');
        } else {
            showModal('查看失败', '邮件详情获取失败', 'error');
        }
    } catch (error) {
        console.error('查看邮件详情失败:', error);
        showModal('查看失败', '网络错误，请重试', 'error');
    }
}

function loadMailHistoryPage(page) {
    if (page < 1) return;
    // 这里可以添加分页逻辑
    loadMailHistory();
}