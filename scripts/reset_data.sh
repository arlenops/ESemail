#!/bin/bash

# ESemail 数据重置脚本
# 用于重新部署时清空所有配置数据

echo "🗑️  正在清空 ESemail 数据..."

# 数据目录
DATA_DIR="./data"

if [ -d "$DATA_DIR" ]; then
    echo "📁 清空数据目录: $DATA_DIR"
    
    # 备份现有数据（可选）
    if [ "$1" = "--backup" ]; then
        BACKUP_DIR="./data_backup_$(date +%Y%m%d_%H%M%S)"
        echo "💾 备份数据到: $BACKUP_DIR"
        cp -r "$DATA_DIR" "$BACKUP_DIR"
        echo "✅ 数据已备份到 $BACKUP_DIR"
    fi
    
    # 清空数据文件
    rm -f "$DATA_DIR"/*.json
    rm -f "$DATA_DIR"/*.db
    rm -rf "$DATA_DIR"/certs/
    rm -rf "$DATA_DIR"/mail/
    rm -rf "$DATA_DIR"/keys/
    
    echo "🧹 已清空以下数据:"
    echo "   - 域名配置 (domains.json)"
    echo "   - 用户配置 (users.json)"  
    echo "   - 工作流状态 (workflow_state.json)"
    echo "   - SSL证书文件"
    echo "   - 邮件数据"
    echo "   - DKIM密钥"
else
    echo "⚠️  数据目录不存在: $DATA_DIR"
fi

echo ""
echo "✅ 数据重置完成！"
echo "🚀 现在可以重新启动 ESemail 进行全新部署"
echo ""
echo "使用方法:"
echo "   bash scripts/reset_data.sh           # 直接清空数据"
echo "   bash scripts/reset_data.sh --backup  # 清空前备份数据"