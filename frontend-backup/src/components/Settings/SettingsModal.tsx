import React from 'react';
import { Modal } from 'antd';
import { useUIStore } from '../../stores/uiStore';

interface SettingsModalProps {
  modalId: string;
}

const SettingsModal: React.FC<SettingsModalProps> = ({ modalId }) => {
  const { closeModal } = useUIStore();

  return (
    <Modal
      title="设置"
      open={true}
      onCancel={() => closeModal(modalId)}
      footer={null}
    >
      <p>设置功能开发中...</p>
    </Modal>
  );
};

export default SettingsModal;