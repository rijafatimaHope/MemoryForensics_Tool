import struct
import logging
from config.config import OFFSET_TASKS, POINTER_SIZE

logger = logging.getLogger(__name__)

class TaskStructIterator:
    """
    Role 1 Core Engine Component.
    Iterates through the doubly linked list of tasks in the Linux memory mapping.
    Yields the physical/virtual layout boundary addresses for Role 2 to parse text definitions from.
    """
    def __init__(self, mapped_memory, init_task_offset):
        self.mapped_memory = mapped_memory
        self.init_task_offset = init_task_offset
        self.visited = set()

    def walk_tasks(self):
        """
        Generator that traverses the tasks.next linked list.
        Yields the absolute address of each discovered task_struct.
        """
        current_task_addr = self.init_task_offset
        
        while True:
            # Shield against circular looping DoS
            if current_task_addr in self.visited:
                logger.warning(f"Circular mapping detected at {hex(current_task_addr)}. Breaking.")
                break
                
            self.visited.add(current_task_addr)
            
            # Yield the current task_struct address for Role 2
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
            
            # Unpack the 64-bit unsigned long long (little-endian)
            next_list_head = struct.unpack("<Q", pointer_bytes)[0]
            
            # If the literal pointer is 0 or invalid, break
            if next_list_head == 0:
                break
                
            # next_list_head points to the OFFSET_TASKS field of the next task_struct.
            # To get the actual next task_struct base address, we subtract the offset.
            current_task_addr = next_list_head - OFFSET_TASKS
            
            # If we looped back to init_task smoothly, we are done
            if current_task_addr == self.init_task_offset:
                break
