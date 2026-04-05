import struct
import logging
from config.config import OFFSET_TASKS, POINTER_SIZE

logger = logging.getLogger(__name__)

class TaskStructIterator:
    """
    Role 1 Core Engine Component.
    Iterates through the doubly linked list of tasks in the Linux memory mapping.
    """
    def __init__(self, mapped_memory, init_task_offset):
        self.mapped_memory = mapped_memory
        self.init_task_offset = init_task_offset
        self.visited = set()

    def walk_tasks(self):
        current_task_addr = self.init_task_offset
        
        while True:
            # Shield against circular looping DoS
            if current_task_addr in self.visited:
                logger.warning(f"Circular mapping detected at {hex(current_task_addr)}. Breaking.")
                break
                
            self.visited.add(current_task_addr)
            
            # Yield the current physical address to Role 2!
            yield current_task_addr
            
            # Find the pointer to the next task's list_head
            next_ptr_addr = current_task_addr + OFFSET_TASKS
            
            # Memory mapping bound check
            if next_ptr_addr + POINTER_SIZE > self.mapped_memory.size():
                logger.error("Out of bounds pointer read.")
                break
                
            # Read 8 bytes
            self.mapped_memory.seek(next_ptr_addr)
            pointer_bytes = self.mapped_memory.read(POINTER_SIZE)
            next_list_head = struct.unpack("<Q", pointer_bytes)[0]
            
            if next_list_head == 0:
                break
                
            # ==========================================
            # THE KASLR HACK: Virtual to Physical Translation
            # ==========================================
            # next_list_head is a Virtual Address like 0xffff88af40921b00
            # By masking with 0xFFFFFFFF, we chop off the top 32 bits 
            # and get the raw Physical offset (e.g., 0x40921b00)
            physical_list_head = next_list_head & 0xFFFFFFFF
            
            # Now we subtract the offset just like normal
            current_task_addr = physical_list_head - OFFSET_TASKS
            
            # If we looped back to where we started, we are done
            if current_task_addr == self.init_task_offset:
                break