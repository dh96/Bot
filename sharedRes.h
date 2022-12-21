#ifndef SHAREDRES_H
#define SHAREDRES_H

#include <windows.h>
#include <list>

class Slock {
    private:
        CRITICAL_SECTION critical_section;
        BOOL ret;

    public:
        Slock();
        ~Slock();
        void lock();
        void unlock();

};

class SharedBool {
    private:
        bool rBool;
        Slock sc;
    public:
        void operator=(const bool &rBool);
        SharedBool &operator=(const SharedBool &sb);
        bool getValue();    
};

template<class T>
class SharedList {
    private:
        std::list<T>list;
        Slock sc;
    public:
        void add(T item);
        void remove(T item);
        void clear();
        std::list<T> getCopy();    
};

template<class T>
void SharedList<T>::add(T item){
    sc.lock();
    list.push_back(item);
    sc.unlock();
}

template<class T>
void SharedList<T>::remove(T item){
    sc.lock();
    list.remove(item);
    sc.unlock();
}

template<class T>
void SharedList<T>::clear() {
    sc.lock();
    list.clear();
    sc.unlock();
}

template<class T>
std::list<T> SharedList<T>::getCopy() {
    sc.lock();
    std::list<T> tmp = list;
    sc.unlock();
    return tmp;
}


#endif