package etf.openpgp.su180295dvv180421d.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public abstract class KeyRing<T> implements Serializable{

    ArrayList<Observer<List<T>>> observers = new ArrayList<>();

    public void addObserver(Observer<List<T>> observer) {
        observers.add(observer);
    }

    protected void notifyObservers(List<T> keys) {
        for (Observer<List<T>> observer:observers) {
            observer.observableChanged(keys);
        }
    }

}
