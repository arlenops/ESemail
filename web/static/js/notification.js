/**
 * 现代化通知系统 - 替换原生alert和confirm
 * 提供美观的自定义UI组件，支持复制功能
 */

class NotificationSystem {
    constructor() {
        this.container = null;
        this.init();
    }

    init() {
        // 创建通知容器
        this.container = document.createElement('div');
        this.container.id = 'notification-container';
        this.container.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
            max-width: 400px;
        `;
        document.body.appendChild(this.container);
    }

    // 显示信息提示
    showInfo(message, title = '提示', duration = 5000) {
        return this.showNotification(message, title, 'info', duration);
    }

    // 显示成功提示
    showSuccess(message, title = '成功', duration = 3000) {
        return this.showNotification(message, title, 'success', duration);
    }

    // 显示警告提示
    showWarning(message, title = '警告', duration = 5000) {
        return this.showNotification(message, title, 'warning', duration);
    }

    // 显示错误提示
    showError(message, title = '错误', duration = 8000) {
        return this.showNotification(message, title, 'error', duration);
    }

    // 显示确认对话框
    showConfirm(message, title = '确认操作', options = {}) {
        return new Promise((resolve) => {
            const modal = this.createModal({
                title: title,
                body: `
                    <div class="text-center">
                        <i class="fas fa-question-circle text-primary fa-3x mb-3"></i>
                        <p class="mb-0">${message}</p>
                    </div>
                `,
                buttons: [
                    {
                        text: options.cancelText || '取消',
                        class: 'btn-secondary',
                        action: () => {
                            this.closeModal(modal);
                            resolve(false);
                        }
                    },
                    {
                        text: options.confirmText || '确认',
                        class: options.dangerConfirm ? 'btn-danger' : 'btn-primary',
                        action: () => {
                            this.closeModal(modal);
                            resolve(true);
                        }
                    }
                ]
            });
        });
    }

    // 显示输入对话框
    showPrompt(message, title = '输入信息', defaultValue = '', options = {}) {
        return new Promise((resolve) => {
            const inputId = 'prompt-input-' + Date.now();
            const modal = this.createModal({
                title: title,
                body: `
                    <div>
                        <p class="mb-3">${message}</p>
                        <input type="${options.inputType || 'text'}"
                               class="form-control"
                               id="${inputId}"
                               placeholder="${options.placeholder || ''}"
                               value="${defaultValue}">
                    </div>
                `,
                buttons: [
                    {
                        text: '取消',
                        class: 'btn-secondary',
                        action: () => {
                            this.closeModal(modal);
                            resolve(null);
                        }
                    },
                    {
                        text: '确定',
                        class: 'btn-primary',
                        action: () => {
                            const input = document.getElementById(inputId);
                            const value = input.value.trim();
                            this.closeModal(modal);
                            resolve(value);
                        }
                    }
                ]
            });

            // 聚焦到输入框
            setTimeout(() => {
                const input = document.getElementById(inputId);
                if (input) {
                    input.focus();
                    input.select();
                }
            }, 300);
        });
    }

    // 显示代码/文本内容对话框（支持复制）
    showCopyableContent(content, title = '内容详情', language = 'text') {
        const contentId = 'copyable-content-' + Date.now();
        const copyBtnId = 'copy-btn-' + Date.now();

        const modal = this.createModal({
            title: title,
            size: 'lg',
            body: `
                <div class="position-relative">
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <small class="text-muted">点击下方按钮复制内容</small>
                        <button type="button" class="btn btn-outline-primary btn-sm" id="${copyBtnId}">
                            <i class="fas fa-copy me-1"></i>复制
                        </button>
                    </div>
                    <pre id="${contentId}" class="bg-light p-3 rounded border" style="max-height: 400px; overflow-y: auto; white-space: pre-wrap; word-break: break-word;"><code>${this.escapeHtml(content)}</code></pre>
                </div>
            `,
            buttons: [
                {
                    text: '关闭',
                    class: 'btn-secondary',
                    action: () => this.closeModal(modal)
                }
            ]
        });

        // 添加复制功能
        setTimeout(() => {
            const copyBtn = document.getElementById(copyBtnId);
            const contentEl = document.getElementById(contentId);

            if (copyBtn && contentEl) {
                copyBtn.addEventListener('click', async () => {
                    try {
                        await navigator.clipboard.writeText(content);
                        copyBtn.innerHTML = '<i class="fas fa-check me-1"></i>已复制';
                        copyBtn.classList.remove('btn-outline-primary');
                        copyBtn.classList.add('btn-success');

                        setTimeout(() => {
                            copyBtn.innerHTML = '<i class="fas fa-copy me-1"></i>复制';
                            copyBtn.classList.remove('btn-success');
                            copyBtn.classList.add('btn-outline-primary');
                        }, 2000);
                    } catch (err) {
                        // 降级处理
                        this.selectText(contentEl);
                        this.showWarning('请手动复制选中的内容', '复制失败');
                    }
                });
            }
        }, 100);
    }

    // 显示通知
    showNotification(message, title, type, duration) {
        const notification = document.createElement('div');
        const notificationId = 'notification-' + Date.now();
        notification.id = notificationId;

        const typeConfig = {
            info: { icon: 'fa-info-circle', class: 'alert-info' },
            success: { icon: 'fa-check-circle', class: 'alert-success' },
            warning: { icon: 'fa-exclamation-triangle', class: 'alert-warning' },
            error: { icon: 'fa-times-circle', class: 'alert-danger' }
        };

        const config = typeConfig[type] || typeConfig.info;

        notification.className = `alert ${config.class} alert-dismissible fade show mb-2`;
        notification.style.cssText = `
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            border: none;
            border-radius: 8px;
        `;

        notification.innerHTML = `
            <div class="d-flex align-items-start">
                <i class="fas ${config.icon} me-2 mt-1"></i>
                <div class="flex-grow-1">
                    <strong>${title}</strong>
                    <div>${message}</div>
                </div>
                <button type="button" class="btn-close" aria-label="Close"></button>
            </div>
        `;

        // 添加关闭事件
        const closeBtn = notification.querySelector('.btn-close');
        closeBtn.addEventListener('click', () => {
            this.removeNotification(notification);
        });

        // 添加到容器
        this.container.appendChild(notification);

        // 自动移除
        if (duration > 0) {
            setTimeout(() => {
                this.removeNotification(notification);
            }, duration);
        }

        return notification;
    }

    // 创建模态框
    createModal({ title, body, buttons = [], size = 'md' }) {
        const modalId = 'custom-modal-' + Date.now();
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.id = modalId;
        modal.tabIndex = -1;

        const sizeClass = {
            sm: 'modal-sm',
            md: '',
            lg: 'modal-lg',
            xl: 'modal-xl'
        }[size] || '';

        modal.innerHTML = `
            <div class="modal-dialog modal-dialog-centered ${sizeClass}">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">${title}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        ${body}
                    </div>
                    <div class="modal-footer">
                        ${buttons.map(btn => `
                            <button type="button" class="btn ${btn.class}" data-action="${btn.text}">
                                ${btn.text}
                            </button>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;

        // 添加按钮事件
        buttons.forEach(btn => {
            const buttonEl = modal.querySelector(`[data-action="${btn.text}"]`);
            if (buttonEl && btn.action) {
                buttonEl.addEventListener('click', btn.action);
            }
        });

        document.body.appendChild(modal);
        const bootstrapModal = new bootstrap.Modal(modal);
        bootstrapModal.show();

        // 模态框关闭时清理DOM
        modal.addEventListener('hidden.bs.modal', () => {
            document.body.removeChild(modal);
        });

        return modal;
    }

    // 关闭模态框
    closeModal(modal) {
        const bootstrapModal = bootstrap.Modal.getInstance(modal);
        if (bootstrapModal) {
            bootstrapModal.hide();
        }
    }

    // 移除通知
    removeNotification(notification) {
        if (notification && notification.parentNode) {
            notification.classList.remove('show');
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 150);
        }
    }

    // 选中文本
    selectText(element) {
        const range = document.createRange();
        range.selectNodeContents(element);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
    }

    // HTML转义
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// 创建全局实例
window.notification = new NotificationSystem();

// 提供便捷的全局函数，替代原生alert和confirm
window.showAlert = (message, title, type = 'info') => {
    switch(type) {
        case 'success': return window.notification.showSuccess(message, title);
        case 'warning': return window.notification.showWarning(message, title);
        case 'error': return window.notification.showError(message, title);
        default: return window.notification.showInfo(message, title);
    }
};

window.showConfirm = (message, title, options) => {
    return window.notification.showConfirm(message, title, options);
};

window.showPrompt = (message, title, defaultValue, options) => {
    return window.notification.showPrompt(message, title, defaultValue, options);
};

window.showCopyableContent = (content, title, language) => {
    return window.notification.showCopyableContent(content, title, language);
};